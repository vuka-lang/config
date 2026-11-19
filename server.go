package config

import (
	"bufio"
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
	Logger     *slog.Logger
}

// Server returns the config server as an http.Handler: it can be mounted in
// a Vuka app or served on its own.
func Server(c ServerConfig) (http.Handler, error) {
	if c.Source == nil || len(c.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("config: Server needs a Source and a signing Key")
	}
	s := &server{ServerConfig: c, tokens: map[string][]byte{}}
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
	return s, nil
}

type server struct {
	ServerConfig
	tokens map[string][]byte
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	app, ok := s.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vuka-config"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req, ok := parseRequest(segs)
	if !ok || req.app != app {
		http.NotFound(w, r)
		return
	}
	tree, err := s.Source.Read(r.Context(), req.label, Files(req.app, req.profile))
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.Logger.Error("config: reading the source", "app", app, "err", err)
		http.Error(w, "source unavailable", http.StatusBadGateway)
		return
	}
	snap, err := Build(req.app, req.profile, tree)
	if err == nil {
		err = snap.Sign(s.Key)
	}
	if err != nil {
		s.Logger.Error("config: building a snapshot", "app", app, "err", err)
		http.Error(w, "invalid configuration", http.StatusInternalServerError)
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
	if len(segs) == 3 {
		r.label = segs[2]
		if !ValidLabel(r.label) {
			return r, false
		}
	}
	return r, ValidApp(r.app) && ValidProfile(r.profile)
}

func (s *server) authenticate(r *http.Request) (string, bool) {
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

func (s *server) hook(w http.ResponseWriter, r *http.Request) {
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
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) hookAuthorized(r *http.Request, body []byte) bool {
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
