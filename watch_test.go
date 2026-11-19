package config_test

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/config/v2/source/gitsrc"
)

type stream struct {
	resp  *http.Response
	lines chan string
}

func (f *fixture) open(t *testing.T, path, token string) *stream {
	t.Helper()
	resp, st := f.tryOpen(t, path, token)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %d %s", path, resp.StatusCode, st)
	}
	return st
}

func (f *fixture) tryOpen(t *testing.T, path, token string) (*http.Response, *stream) {
	t.Helper()
	req, _ := http.NewRequest("GET", f.srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	st := &stream{resp: resp, lines: make(chan string, 256)}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		st.lines <- string(b)
		return resp, st
	}
	t.Cleanup(func() { resp.Body.Close() })
	go func() {
		defer close(st.lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			st.lines <- sc.Text()
		}
	}()
	return resp, st
}

func (s *stream) String() string {
	select {
	case l := <-s.lines:
		return l
	default:
		return ""
	}
}

// version returns the next announced version, skipping comments.
func (s *stream) version(t *testing.T, within time.Duration) string {
	t.Helper()
	deadline := time.After(within)
	event := ""
	for {
		select {
		case l, ok := <-s.lines:
			if !ok {
				t.Fatal("the stream ended")
			}
			switch {
			case strings.HasPrefix(l, "event: "):
				event = strings.TrimPrefix(l, "event: ")
			case strings.HasPrefix(l, "data: "):
				if event != "version" {
					t.Fatalf("data of event %q", event)
				}
				return strings.TrimPrefix(l, "data: ")
			}
		case <-deadline:
			t.Fatal("no version announced")
		}
	}
}

func (s *stream) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case l, ok := <-s.lines:
			if !ok {
				t.Fatal("the stream ended")
			}
			if strings.HasPrefix(l, "data: ") {
				t.Fatalf("an unexpected version: %s", l)
			}
		case <-deadline:
			return
		}
	}
}

func (s *stream) ends(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case _, ok := <-s.lines:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("the stream is still open")
		}
	}
}

func snapshotVersion(t *testing.T, f *fixture, path, token string) string {
	t.Helper()
	code, hdr, _ := f.get(t, path, token)
	if code != 200 {
		t.Fatalf("%s: %d", path, code)
	}
	return hdr.Get("X-Config-Version")
}

func fast(c *config.ServerConfig) { c.WatchInterval = 20 * time.Millisecond }

func TestWatchDirVersions(t *testing.T) {
	f := newFixture(t, fast)
	tok := f.tokens["orders"]
	s := f.open(t, "/orders/production/watch", tok)
	resp := s.resp
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", resp.Header)
	}
	v1 := s.version(t, 2*time.Second)
	if v1 != snapshotVersion(t, f, "/orders/production", tok) {
		t.Errorf("connect version %q is not the snapshot's", v1)
	}

	os.WriteFile(filepath.Join(f.dir, "orders/.env.production"), []byte("RATE=200\n"), 0o644)
	v2 := s.version(t, 2*time.Second)
	if v2 == v1 || v2 != snapshotVersion(t, f, "/orders/production", tok) {
		t.Errorf("after an edit: %q, snapshot %q", v2, snapshotVersion(t, f, "/orders/production", tok))
	}

	os.WriteFile(filepath.Join(f.dir, "billing/.env"), []byte("BILLING_KEY=changed\n"), 0o644)
	os.WriteFile(filepath.Join(f.dir, ".env.staging"), []byte("OTHER=1\n"), 0o644)
	s.quiet(t, 200*time.Millisecond)

	os.WriteFile(filepath.Join(f.dir, ".env"), []byte("MAIL_HOST=other\n"), 0o644)
	if v3 := s.version(t, 2*time.Second); v3 == v2 {
		t.Error("a shared file's change was not announced")
	}

	os.Remove(filepath.Join(f.dir, "orders/.env.production"))
	if v4 := s.version(t, 2*time.Second); v4 != snapshotVersion(t, f, "/orders/production", tok) {
		t.Error("a removed file was not announced")
	}
}

func TestWatchNoProfileAndTwoProfilesApart(t *testing.T) {
	f := newFixture(t, fast)
	tok := f.tokens["orders"]
	none := f.open(t, "/orders/-/watch", tok)
	prod := f.open(t, "/orders/production/watch", tok)
	none.version(t, 2*time.Second)
	prod.version(t, 2*time.Second)
	os.WriteFile(filepath.Join(f.dir, "orders/.env.production"), []byte("RATE=300\n"), 0o644)
	prod.version(t, 2*time.Second)
	none.quiet(t, 150*time.Millisecond)
}

func TestWatchHeartbeat(t *testing.T) {
	f := newFixture(t, func(c *config.ServerConfig) { c.WatchHeartbeat = 30 * time.Millisecond })
	s := f.open(t, "/orders/production/watch", f.tokens["orders"])
	s.version(t, 2*time.Second)
	deadline := time.After(2 * time.Second)
	for n := 0; n < 3; {
		select {
		case l := <-s.lines:
			if strings.HasPrefix(l, ":") {
				n++
			}
		case <-deadline:
			t.Fatal("no heartbeats")
		}
	}
}

func TestWatchAccess(t *testing.T) {
	f := newFixture(t, fast)
	orders, billing := f.tokens["orders"], f.tokens["billing"]
	_, _, want404 := f.get(t, "/orders/production/nope", billing)
	for name, c := range map[string]struct {
		path, token string
		code        int
	}{
		"no token":            {"/orders/production/watch", "", 401},
		"wrong token":         {"/orders/production/watch", "nope", 401},
		"another app's token": {"/orders/production/watch", billing, 404},
		"unknown app":         {"/nobody/production/watch", orders, 404},
		"unknown label":       {"/orders/production/watch?label=v42", orders, 404},
		"bad label":           {"/orders/production/watch?label=..%2Fx", orders, 404},
		"flag as label":       {"/orders/production/watch?label=--upload-pack=x", orders, 404},
		"bad profile":         {"/orders/-x/watch", orders, 404},
		"too deep":            {"/orders/production/main/watch", orders, 404},
		"the app's own":       {"/orders/production/watch", orders, 200},
		"the other's own":     {"/billing/production/watch", billing, 200},
	} {
		resp, st := f.tryOpen(t, c.path, c.token)
		if resp.StatusCode != c.code {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, c.code)
		}
		if c.code == 404 && c.token != "" && strings.TrimSpace(st.String()) != strings.TrimSpace(string(want404)) {
			t.Errorf("%s: the 404 differs from a snapshot's: %q", name, st.String())
		}
	}
	req, _ := http.NewRequest("POST", f.srv.URL+"/orders/production/watch", nil)
	req.Header.Set("Authorization", "Bearer "+orders)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 405 {
		t.Errorf("POST: %v %v", resp, err)
	}
	// A watcher of another app never sees this one's changes.
	other := f.open(t, "/billing/production/watch", billing)
	other.version(t, 2*time.Second)
	os.WriteFile(filepath.Join(f.dir, "orders/.env"), []byte("ORDERS_DB=moved\n"), 0o644)
	other.quiet(t, 150*time.Millisecond)
}

func TestWatchCaps(t *testing.T) {
	f := newFixture(t, func(c *config.ServerConfig) { c.WatchPerApp, c.WatchTotal = 2, 3 })
	orders, billing := f.tokens["orders"], f.tokens["billing"]
	a := f.open(t, "/orders/production/watch", orders)
	f.open(t, "/orders/production/watch", orders)
	a.version(t, 2*time.Second)

	resp, _ := f.tryOpen(t, "/orders/production/watch", orders)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Errorf("third watcher of one token: %d %v", resp.StatusCode, resp.Header)
	}
	// The cap is per token; another app still gets in, until the total is reached.
	f.open(t, "/billing/production/watch", billing)
	resp, _ = f.tryOpen(t, "/billing/production/watch", billing)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Errorf("beyond the total: %d %v", resp.StatusCode, resp.Header)
	}
	// An unauthorised or unknown request is not told about the caps.
	if resp, _ = f.tryOpen(t, "/orders/production/watch", billing); resp.StatusCode != 404 {
		t.Errorf("another app's token at the cap: %d", resp.StatusCode)
	}

	a.resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, st := f.tryOpen(t, "/orders/production/watch", orders)
		if resp.StatusCode == 200 {
			st.version(t, 2*time.Second)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a slot is never freed: %d", resp.StatusCode)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type countingSource struct {
	config.Source
	reads atomic.Int64
}

func (c *countingSource) Read(ctx context.Context, label string, names []string) (config.Tree, error) {
	c.reads.Add(1)
	return c.Source.Read(ctx, label, names)
}

func TestWatchSharesOneComputation(t *testing.T) {
	var src *countingSource
	f := newFixture(t, func(c *config.ServerConfig) {
		src = &countingSource{Source: c.Source}
		c.Source, c.WatchInterval, c.WatchPerApp = src, 50*time.Millisecond, 100
	})
	tok := f.tokens["orders"]
	var streams []*stream
	for range 40 {
		streams = append(streams, f.open(t, "/orders/production/watch", tok))
	}
	for _, s := range streams {
		s.version(t, 2*time.Second)
	}
	before := src.reads.Load()
	time.Sleep(500 * time.Millisecond)
	if n := src.reads.Load() - before; n > 20 {
		t.Errorf("%d source reads in 500ms for 40 watchers of one snapshot at 50ms", n)
	}
	os.WriteFile(filepath.Join(f.dir, "orders/.env"), []byte("ORDERS_DB=shared\n"), 0o644)
	want := snapshotVersion(t, f, "/orders/production", tok)
	for i, s := range streams {
		if v := s.version(t, 2*time.Second); v != want {
			t.Errorf("watcher %d: %q, want %q", i, v, want)
		}
	}

	for _, s := range streams {
		s.resp.Body.Close()
	}
	time.Sleep(200 * time.Millisecond)
	idle := src.reads.Load()
	time.Sleep(300 * time.Millisecond)
	if n := src.reads.Load() - idle; n > 1 {
		t.Errorf("%d reads with no watcher left", n)
	}
}

func TestWatchCloseEndsStreams(t *testing.T) {
	f := newFixture(t, func(c *config.ServerConfig) { c.WatchInterval = time.Hour })
	s := f.open(t, "/orders/production/watch", f.tokens["orders"])
	s.version(t, 2*time.Second)
	f.handler.Close()
	s.ends(t, 2*time.Second)
	resp, _ := f.tryOpen(t, "/orders/production/watch", f.tokens["orders"])
	if resp.StatusCode != 503 {
		t.Errorf("after Close: %d", resp.StatusCode)
	}
	if code, _, _ := f.get(t, "/orders/production", f.tokens["orders"]); code != 200 {
		t.Errorf("snapshots after Close: %d", code)
	}
	f.handler.Close()
}

func TestWatchHTTPServerShutdown(t *testing.T) {
	f := newFixture(t, nil)
	s := f.open(t, "/orders/production/watch", f.tokens["orders"])
	s.version(t, 2*time.Second)
	f.srv.Config.RegisterOnShutdown(f.handler.Close)
	done := make(chan struct{})
	go func() { f.srv.Config.Shutdown(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown waits for the stream")
	}
}

func TestWatchSourceFailureKeepsVersion(t *testing.T) {
	var broken atomic.Bool
	var logs strings.Builder
	f := newFixture(t, func(c *config.ServerConfig) {
		c.WatchInterval = 20 * time.Millisecond
		c.Source = flaky{c.Source, &broken}
		c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	tok := f.tokens["orders"]
	s := f.open(t, "/orders/production/watch", tok)
	s.version(t, 2*time.Second)
	broken.Store(true)
	s.quiet(t, 150*time.Millisecond)
	broken.Store(false)
	s.quiet(t, 100*time.Millisecond)
	if n := strings.Count(logs.String(), "watching a snapshot"); n != 1 {
		t.Errorf("logged %d times:\n%s", n, logs.String())
	}
}

type flaky struct {
	config.Source
	broken *atomic.Bool
}

func (f flaky) Read(ctx context.Context, label string, names []string) (config.Tree, error) {
	if f.broken.Load() {
		return config.Tree{}, io.ErrUnexpectedEOF
	}
	return f.Source.Read(ctx, label, names)
}

func TestWatchGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	for name, viaHook := range map[string]bool{"hook": true, "poll": false} {
		t.Run(name, func(t *testing.T) {
			repo := t.TempDir()
			git := func(args ...string) {
				t.Helper()
				cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			commit := func(body string) {
				os.MkdirAll(filepath.Join(repo, "orders"), 0o755)
				os.WriteFile(filepath.Join(repo, "orders/.env"), []byte(body), 0o644)
				git("add", "-A")
				git("commit", "-q", "-m", "c")
			}
			git("init", "-q", "-b", "main")
			commit("A=1\n")
			git("branch", "other")
			src, err := gitsrc.Open(context.Background(), gitsrc.Options{URL: repo, Dir: filepath.Join(t.TempDir(), "m")})
			if err != nil {
				t.Fatal(err)
			}
			f := newFixture(t, func(c *config.ServerConfig) {
				c.Source, c.HookSecret = src, "s3cret"
				c.WatchInterval = 20 * time.Millisecond
				if viaHook {
					c.WatchInterval = time.Hour
				}
			})
			tok := f.tokens["orders"]
			main := f.open(t, "/orders/production/watch", tok)
			other := f.open(t, "/orders/production/watch?label=other", tok)
			v1 := main.version(t, 2*time.Second)
			other.version(t, 2*time.Second)
			if len(v1) != 40 {
				t.Errorf("version %q is not a commit", v1)
			}

			commit("A=2\n")
			if viaHook {
				main.quiet(t, 100*time.Millisecond)
				req, _ := http.NewRequest("POST", f.srv.URL+"/_hooks/git", strings.NewReader("{}"))
				req.Header.Set("X-Hook-Token", "s3cret")
				resp, err := http.DefaultClient.Do(req)
				if err != nil || resp.StatusCode != 204 {
					t.Fatalf("hook: %v %v", resp, err)
				}
			} else if err := src.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			v2 := main.version(t, 2*time.Second)
			if v2 == v1 || len(v2) != 40 {
				t.Errorf("after a commit: %q", v2)
			}
			other.quiet(t, 100*time.Millisecond) // its branch didn't move
		})
	}
}
