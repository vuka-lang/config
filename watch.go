package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	defaultWatchInterval  = 3 * time.Second
	defaultWatchHeartbeat = 25 * time.Second
	defaultWatchPerApp    = 16
	defaultWatchTotal     = 2000
	watchWriteTimeout     = 10 * time.Second
)

var (
	errWatchApp    = errors.New("too many watchers for this token")
	errWatchTotal  = errors.New("too many watchers")
	errWatchClosed = errors.New("server is shutting down")
)

type watchKey struct{ app, profile, label string }

// watchHub shares one computation of a snapshot's version between every
// stream that watches it.
type watchHub struct {
	s      *Handler
	closed chan struct{}
	once   sync.Once

	mu     sync.Mutex
	groups map[watchKey]*watchGroup
	perApp map[string]int
	total  int
}

type watchGroup struct {
	key     watchKey
	ready   chan struct{}
	err     error // set before ready closes
	version string
	subs    map[*subscriber]struct{}
	kick    chan struct{}
	stop    chan struct{}
}

type subscriber struct{ ch chan string }

func newWatchHub(s *Handler) *watchHub {
	return &watchHub{s: s, closed: make(chan struct{}), groups: map[watchKey]*watchGroup{}, perApp: map[string]int{}}
}

// Close ends every stream the handler has open and refuses new ones. It is
// safe to call more than once.
func (s *Handler) Close() { s.watch.once.Do(func() { close(s.watch.closed) }) }

func (h *watchHub) interval() time.Duration {
	if h.s.WatchInterval > 0 {
		return h.s.WatchInterval
	}
	return defaultWatchInterval
}

func capOf(n, def int) int {
	if n == 0 {
		return def
	}
	return n
}

// kick makes every watched snapshot be read again now.
func (h *watchHub) kick() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, g := range h.groups {
		select {
		case g.kick <- struct{}{}:
		default:
		}
	}
}

// join registers a watcher of key and returns the version it starts from.
func (h *watchHub) join(key watchKey) (*watchGroup, *subscriber, string, error) {
	h.mu.Lock()
	select {
	case <-h.closed:
		h.mu.Unlock()
		return nil, nil, "", errWatchClosed
	default:
	}
	if n := capOf(h.s.WatchTotal, defaultWatchTotal); n > 0 && h.total >= n {
		h.mu.Unlock()
		return nil, nil, "", errWatchTotal
	}
	if n := capOf(h.s.WatchPerApp, defaultWatchPerApp); n > 0 && h.perApp[key.app] >= n {
		h.mu.Unlock()
		return nil, nil, "", errWatchApp
	}
	g, created := h.groups[key], false
	if g == nil {
		g = &watchGroup{key: key, ready: make(chan struct{}), subs: map[*subscriber]struct{}{}, kick: make(chan struct{}, 1), stop: make(chan struct{})}
		h.groups[key] = g
		created = true
	}
	sub := &subscriber{ch: make(chan string, 1)}
	g.subs[sub] = struct{}{}
	h.total++
	h.perApp[key.app]++
	h.mu.Unlock()

	if created {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		v, err := h.version(ctx, key)
		cancel()
		h.mu.Lock()
		g.version, g.err = v, err
		h.mu.Unlock()
		close(g.ready)
		if err == nil {
			go h.run(g)
		}
	}
	<-g.ready
	if g.err != nil {
		h.leave(g, sub)
		return nil, nil, "", g.err
	}
	h.mu.Lock()
	v := g.version
	h.mu.Unlock()
	return g, sub, v, nil
}

func (h *watchHub) leave(g *watchGroup, sub *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := g.subs[sub]; !ok {
		return
	}
	delete(g.subs, sub)
	h.total--
	if h.perApp[g.key.app]--; h.perApp[g.key.app] <= 0 {
		delete(h.perApp, g.key.app)
	}
	if len(g.subs) == 0 {
		if h.groups[g.key] == g {
			delete(h.groups, g.key)
		}
		close(g.stop)
	}
}

func (h *watchHub) version(ctx context.Context, key watchKey) (string, error) {
	snap, err := h.s.snapshot(ctx, request{app: key.app, profile: key.profile, label: key.label}, false)
	if err != nil {
		return "", err
	}
	return snap.Version, nil
}

// run reads the snapshot's version while the group has watchers and hands a
// new one to each of them. A read that fails is logged once and the last
// version stands.
func (h *watchHub) run(g *watchGroup) {
	t := time.NewTicker(h.interval())
	defer t.Stop()
	failed := ""
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
		case <-g.kick:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		v, err := h.version(ctx, g.key)
		cancel()
		if err != nil {
			if msg := err.Error(); msg != failed {
				failed = msg
				h.s.Logger.Error("config: watching a snapshot", "app", g.key.app, "err", err)
			}
			continue
		}
		failed = ""
		h.mu.Lock()
		if v != g.version {
			g.version = v
			for sub := range g.subs {
				select {
				case <-sub.ch:
				default:
				}
				sub.ch <- v
			}
		}
		h.mu.Unlock()
	}
}

// watchRequest serves GET /{app}/{profile}/watch[?label=…] as a stream of
// server-sent events: "event: version" with the snapshot's version as data,
// once on connect and on every change, and a comment line while idle.
func (s *Handler) watchRequest(w http.ResponseWriter, r *http.Request, app string, segs []string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	profile, err := url.PathUnescape(segs[1])
	if err != nil || segs[0] != app || !ValidApp(app) {
		http.NotFound(w, r)
		return
	}
	if profile == NoProfile {
		profile = ""
	}
	label := r.URL.Query().Get("label")
	if !ValidProfile(profile) || label != "" && !ValidLabel(label) {
		http.NotFound(w, r)
		return
	}
	g, sub, version, err := s.watch.join(watchKey{app, profile, label})
	switch {
	case errors.Is(err, errWatchApp):
		w.Header().Set("Retry-After", "5")
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	case errors.Is(err, errWatchTotal), errors.Is(err, errWatchClosed):
		w.Header().Set("Retry-After", "5")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case err != nil:
		s.refuse(w, r, app, err)
		return
	}
	defer s.watch.leave(g, sub)

	rc := http.NewResponseController(w)
	write := func(format string, args ...any) bool {
		rc.SetWriteDeadline(time.Now().Add(watchWriteTimeout))
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	last := version
	if !write("event: version\ndata: %s\n\n", version) {
		return
	}
	beat := time.NewTicker(capDuration(s.WatchHeartbeat, defaultWatchHeartbeat))
	defer beat.Stop()
	for {
		select {
		case v := <-sub.ch:
			if v != last {
				last = v
				if !write("event: version\ndata: %s\n\n", v) {
					return
				}
			}
		case <-beat.C:
			if !write(": keepalive\n\n") {
				return
			}
		case <-r.Context().Done():
			return
		case <-s.watch.closed:
			return
		}
	}
}

func capDuration(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
