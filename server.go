package config

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ServerConfig configures Server.
type ServerConfig struct {
	Source Source
	// Key signs every snapshot.
	Key ed25519.PrivateKey
	// Tokens maps each app to the hex SHA-256 of its token (see ParseTokens).
	Tokens map[string]string
	// HookSecret, when set, enables POST /_hooks/git for a Source that is a
	// Refresher. It is compared with the X-Hook-Token or X-Gitlab-Token
	// header, or checked as the HMAC of the body in X-Hub-Signature-256.
	HookSecret string
	// AppKeys maps each app to the public key its values are encrypted to
	// (see ParseAppKeys); GET /_keys/{app} serves them, signed.
	AppKeys map[string]*SecretPublicKey
	// WatchInterval is how often a watched snapshot is read again to see
	// whether its version moved; zero is 3s. A Refresher's hook reads at once.
	WatchInterval time.Duration
	// WatchHeartbeat is the gap between the comments that keep an idle
	// stream open through proxies; zero is 25s.
	WatchHeartbeat time.Duration
	// WatchPerApp and WatchTotal cap the streams one app's token, and the
	// server, hold open; zero is 16 and 2000, negative no cap.
	WatchPerApp, WatchTotal int
	// DecryptKey, when set, makes the server decrypt the cipher values
	// encrypted to it before serving them (signed after), for clients that
	// can't. The server can then read those secrets. Values encrypted to an
	// app key pass through.
	DecryptKey *SecretKey
	Logger     *slog.Logger
}

// Server returns the config server as an http.Handler: it can be mounted in
// a Vuka app or served on its own.
func Server(c ServerConfig) (*Handler, error) {
	if c.Source == nil || len(c.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("config: Server needs a Source and a signing Key")
	}
	s := &Handler{ServerConfig: c, tokens: map[string][]byte{}}
	s.watch = newWatchHub(s)
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	for app, h := range c.Tokens {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size || !ValidApp(app) {
			return nil, fmt.Errorf("config: token of %q: want a valid app name and a hex SHA-256", app)
		}
		s.tokens[app] = b
	}
	for app, k := range c.AppKeys {
		if k == nil || !ValidApp(app) {
			return nil, fmt.Errorf("config: key of %q: want a valid app name and a public key", app)
		}
	}
	return s, nil
}

// Handler is the config server's http.Handler. Close ends the streams it has
// open (see ServerConfig.WatchInterval), which http.Server.Shutdown waits
// for otherwise: register it with RegisterOnShutdown.
type Handler struct {
	ServerConfig
	tokens map[string][]byte
	watch  *watchHub
}

func (s *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	segs := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	if len(segs) == 2 && segs[0] == "_hooks" && segs[1] == "git" {
		s.hook(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if segs[0] == "_keys" {
		s.keys(w, r, segs)
		return
	}
	app, ok := s.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vuka-config"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if len(segs) == 3 && segs[2] == "watch" {
		s.watchRequest(w, r, app, segs)
		return
	}
	req, ok := parseRequest(segs)
	if !ok || req.app != app {
		http.NotFound(w, r)
		return
	}
	snap, err := s.snapshot(r.Context(), req, true)
	if err == nil {
		err = snap.Sign(s.Key)
	}
	if err != nil {
		s.refuse(w, r, app, err)
		return
	}
	w.Header().Set("X-Config-Version", snap.Version)
	if req.env {
		body := FormatEnv(snap.Values)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Config-Signature", SignEnv(s.Key, body))
		w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}

type sourceError struct{ err error }

func (e *sourceError) Error() string { return e.err.Error() }

// snapshot reads the source and merges req's files; with decrypt, values
// encrypted to the server's key are opened.
func (s *Handler) snapshot(ctx context.Context, req request, decrypt bool) (*Snapshot, error) {
	tree, err := s.Source.Read(ctx, req.label, Files(req.app, req.profile))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, &sourceError{err}
	}
	snap, err := Build(req.app, req.profile, tree)
	if err == nil && decrypt && s.DecryptKey != nil {
		err = decryptSnapshot(snap, s.DecryptKey)
	}
	return snap, err
}

// refuse answers a failed snapshot: the same status and words wherever it
// was asked for.
func (s *Handler) refuse(w http.ResponseWriter, r *http.Request, app string, err error) {
	var se *sourceError
	switch {
	case errors.Is(err, ErrNotFound):
		http.NotFound(w, r)
	case errors.As(err, &se):
		s.Logger.Error("config: reading the source", "app", app, "err", err)
		http.Error(w, "source unavailable", http.StatusBadGateway)
	case errors.Is(err, ErrSharedSecret) || errors.Is(err, errServerDecrypt):
		s.Logger.Error("config: refusing a snapshot", "app", app, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		s.Logger.Error("config: building a snapshot", "app", app, "err", err)
		http.Error(w, "invalid configuration", http.StatusInternalServerError)
	}
}

var errServerDecrypt = errors.New("config: the server can't decrypt a value")

func decryptSnapshot(snap *Snapshot, key *SecretKey) error {
	open := func(file, name, v string) (string, error) {
		if !IsCipher(v) {
			return v, nil
		}
		if id, err := CipherKeyID(v); err == nil && id != key.id {
			return v, nil
		}
		pt, err := Decrypt([]*SecretKey{key}, snap.App, name, v)
		if err != nil {
			return "", fmt.Errorf("%w: %s: %s: %v", errServerDecrypt, file, name, err)
		}
		return pt, nil
	}
	for i := range snap.Sources {
		l := &snap.Sources[i]
		for k, v := range l.Values {
			pt, err := open(l.File, k, v)
			if err != nil {
				return err
			}
			l.Values[k] = pt
		}
	}
	for k, v := range snap.Values {
		pt, err := open("merged values", k, v)
		if err != nil {
			return err
		}
		snap.Values[k] = pt
	}
	return nil
}

// keys serves the public keys values are encrypted to: /_keys/{app} for an
// app's, /_keys for the server's decryption key. They are public, but
// signed, so a client that holds the server's signing key can tell a key
// that was substituted on the way. Anything else is a plain 404.
func (s *Handler) keys(w http.ResponseWriter, r *http.Request, segs []string) {
	var pub *SecretPublicKey
	var subject string
	switch len(segs) {
	case 1:
		if s.DecryptKey != nil {
			pub, subject = s.DecryptKey.Public(), ServerSubject
		}
	case 2:
		if app, err := url.PathUnescape(segs[1]); err == nil && ValidApp(app) {
			pub, subject = s.AppKeys[app], AppSubject(app)
		}
	}
	if pub == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signKey(s.Key, subject, pub))
}

type request struct {
	app, profile, label string
	env                 bool
}

func parseRequest(segs []string) (request, bool) {
	if len(segs) < 2 || len(segs) > 3 {
		return request{}, false
	}
	var r request
	for i, seg := range segs {
		v, err := url.PathUnescape(seg)
		if err != nil {
			return r, false
		}
		segs[i] = v
	}
	last := len(segs) - 1
	if strings.HasSuffix(segs[last], ".env") {
		r.env = true
		segs[last] = strings.TrimSuffix(segs[last], ".env")
	}
	r.app, r.profile = segs[0], segs[1]
	if r.profile == NoProfile {
		r.profile = ""
	}
	if len(segs) == 3 {
		r.label = segs[2]
		if !ValidLabel(r.label) {
			return r, false
		}
	}
	return r, ValidApp(r.app) && ValidProfile(r.profile)
}

func (s *Handler) authenticate(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	sum := sha256.Sum256([]byte(h[len(prefix):]))
	found := ""
	for app, want := range s.tokens {
		if subtle.ConstantTimeCompare(sum[:], want) == 1 {
			found = app
		}
	}
	return found, found != ""
}

func (s *Handler) hook(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.Source.(Refresher)
	if r.Method != http.MethodPost || s.HookSecret == "" || !ok {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || !s.hookAuthorized(r, body) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := ref.Refresh(r.Context()); err != nil {
		s.Logger.Error("config: refreshing the source", "err", err)
		http.Error(w, "refresh failed", http.StatusBadGateway)
		return
	}
	s.watch.kick()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Handler) hookAuthorized(r *http.Request, body []byte) bool {
	want := sha256.Sum256([]byte(s.HookSecret))
	for _, h := range []string{"X-Hook-Token", "X-Gitlab-Token"} {
		if v := r.Header.Get(h); v != "" {
			got := sha256.Sum256([]byte(v))
			return subtle.ConstantTimeCompare(got[:], want[:]) == 1
		}
	}
	if sig, ok := strings.CutPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256="); ok {
		got, err := hex.DecodeString(sig)
		m := hmac.New(sha256.New, []byte(s.HookSecret))
		m.Write(body)
		return err == nil && hmac.Equal(got, m.Sum(nil))
	}
	return false
}

// NewToken returns a new random app token.
func NewToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns the hex SHA-256 of token, the form Tokens holds.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ParseTokens reads app=hash entries, one per line or separated by commas;
// blank lines and # comments are ignored.
func ParseTokens(text string) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		for _, e := range strings.Split(line, ",") {
			if e = strings.TrimSpace(e); e == "" {
				continue
			}
			app, hash, ok := strings.Cut(e, "=")
			app, hash = strings.TrimSpace(app), strings.TrimSpace(hash)
			if b, err := hex.DecodeString(hash); !ok || err != nil || len(b) != sha256.Size || !ValidApp(app) {
				return nil, fmt.Errorf("config: tokens: want app=<hex sha-256>, got an entry for %q", app)
			}
			out[app] = hash
		}
	}
	return out, sc.Err()
}
