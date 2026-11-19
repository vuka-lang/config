package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vuka-lang/config/v2"
	_ "github.com/vuka-lang/config/v2/client"
	"github.com/vuka-lang/config/v2/source/dirsrc"
	"github.com/vuka-lang/web/v2"
)

// The test binary doubles as the app: run with CLIENT_PROBE set it prints
// the environment the client left, after the package's init has run.
func TestMain(m *testing.M) {
	if keys := os.Getenv("CLIENT_PROBE"); keys != "" {
		out := map[string]string{}
		for _, k := range strings.Split(keys, ",") {
			out[k] = os.Getenv(k)
			out["web:"+k] = web.Env[string](k, "default")
		}
		json.NewEncoder(os.Stdout).Encode(out)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const (
	token        = "orders-token-s3cr3t"
	billingToken = "billing-token-s3cr3t"
)

type server struct {
	*httptest.Server
	pub  string
	priv ed25519.PrivateKey
	hits atomic.Int32
}

func newServer(t *testing.T, files map[string]string, wrap func(http.Handler) http.Handler) *server {
	t.Helper()
	return newServerCfg(t, files, wrap, nil)
}

func newServerCfg(t *testing.T, files map[string]string, wrap func(http.Handler) http.Handler, cfg func(*config.ServerConfig)) *server {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	src, _ := dirsrc.New(dir)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := config.ServerConfig{
		Source: src, Key: priv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tokens: map[string]string{"orders": config.HashToken(token), "billing": config.HashToken(billingToken)},
	}
	if cfg != nil {
		cfg(&c)
	}
	h, err := config.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{priv: priv, pub: base64.StdEncoding.EncodeToString(pub)}
	var handler http.Handler = h
	if wrap != nil {
		handler = wrap(h)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

var served = map[string]string{
	".env":                   "A=server-shared\nSHARED=1\nVUKA_ENV=evil\nVUKA_DEV=1\n",
	"orders/.env.production": "B=server-orders\nREAL=server\nD=server-d\nTOKEN_ECHO=$ORDERS_NOTHING\nPASSWORD=hunter2-from-server\n",
}

type run struct {
	dir, cache string
	env        map[string]string
}

func newRun(t *testing.T, s *server) *run {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("A=file\nB=file\nC=file\nREAL=file\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module app\n"), 0o644)
	r := &run{dir: dir, cache: filepath.Join(dir, "cache", "orders.snapshot"), env: map[string]string{
		"VUKA_CONFIG_URI": s.URL, "VUKA_CONFIG_TOKEN": token, "VUKA_CONFIG_KEY": s.pub,
		"VUKA_APP": "orders", "VUKA_ENV": "production", "VUKA_CONFIG_CACHE": filepath.Join(dir, "cache", "orders.snapshot"),
		"REAL": "real", "CLIENT_PROBE": "A,B,C,D,SHARED,REAL,VUKA_ENV,VUKA_DEV,NONE",
	}}
	return r
}

type result struct {
	env    map[string]string
	stderr string
	code   int
	took   time.Duration
}

func (r *run) exec(t *testing.T) result {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Dir = r.dir
	cmd.Env = []string{"HOME=" + r.dir, "PATH=" + os.Getenv("PATH")}
	for k, v := range r.env {
		if v != "-" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	res := result{stderr: stderr.String(), took: time.Since(start)}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if res.code == 0 {
		if err := json.Unmarshal(stdout.Bytes(), &res.env); err != nil {
			t.Fatalf("%v: %q\n%s", err, stdout.String(), res.stderr)
		}
	}
	return res
}

func checkLogs(t *testing.T, res result) {
	t.Helper()
	for _, secret := range []string{token, "hunter2-from-server", "server-orders", "server-shared", "from-file"} {
		if strings.Contains(res.stderr, secret) {
			t.Errorf("the log holds %q:\n%s", secret, res.stderr)
		}
	}
}

func want(t *testing.T, res result, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if res.env[k] != v {
			t.Errorf("%s = %q, want %q\n%s", k, res.env[k], v, res.stderr)
		}
	}
}

func TestPrecedence(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	res := newRun(t, s).exec(t)
	want(t, res, map[string]string{
		"REAL":       "real",          // the real environment beats the server and the file
		"A":          "server-shared", // the server beats the env file
		"B":          "server-orders", // and the narrower server file beats the shared one
		"C":          "file",          // a file key the server doesn't have stays
		"D":          "server-d",
		"SHARED":     "1",
		"VUKA_ENV":   "production", // reserved keys only come from the real environment
		"VUKA_DEV":   "",
		"NONE":       "",
		"web:NONE":   "default", // the default in code comes last
		"web:A":      "server-shared",
		"web:REAL":   "real",
		"web:SHARED": "1",
	})
	checkLogs(t, res)
}

func TestNothingWithoutURI(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	r := newRun(t, s)
	r.env["VUKA_CONFIG_URI"] = "-"
	res := r.exec(t)
	want(t, res, map[string]string{"A": "file", "B": "file", "D": "", "REAL": "real"})
	if s.hits.Load() != 0 || res.stderr != "" {
		t.Errorf("hits %d, log %q", s.hits.Load(), res.stderr)
	}
	if _, err := os.Stat(r.cache); err == nil {
		t.Error("wrote a cache")
	}
}

func TestSealedCache(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	r := newRun(t, s)
	r.exec(t)
	info, err := os.Stat(r.cache)
	if err != nil {
		t.Fatalf("no cache: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("cache mode %v", info.Mode().Perm())
	}
	sealed, _ := os.ReadFile(r.cache)
	for _, plain := range []string{"server-orders", "server-shared", "hunter2", "orders", "signature"} {
		if bytes.Contains(sealed, []byte(plain)) {
			t.Errorf("the cache holds %q in the clear", plain)
		}
	}

	s.Close() // the server is down: the cache stands in
	res := r.exec(t)
	want(t, res, map[string]string{"A": "server-shared", "B": "server-orders", "C": "file", "REAL": "real", "VUKA_ENV": "production"})
	if !strings.Contains(res.stderr, "cached snapshot") || !strings.Contains(res.stderr, "127.0.0.1") {
		t.Errorf("log: %q", res.stderr)
	}
	checkLogs(t, res)
	if res.took > 20*time.Second {
		t.Errorf("took %v", res.took)
	}
}

func TestCacheRejected(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	r := newRun(t, s)
	r.exec(t)
	good, _ := os.ReadFile(r.cache)
	s.Close()

	flipped := append([]byte(nil), good...)
	flipped[len(flipped)/2] ^= 1
	other := newServer(t, map[string]string{"orders/.env.production": "A=forged\n"}, nil)
	otherRun := newRun(t, other)
	otherRun.cache = r.cache
	otherRun.env["VUKA_CONFIG_CACHE"] = r.cache
	otherRun.exec(t) // a snapshot of another server, sealed with the same token
	forged, _ := os.ReadFile(r.cache)

	for name, c := range map[string][]byte{"flipped bit": flipped, "truncated": good[:8], "empty": nil, "other server's": forged} {
		os.WriteFile(r.cache, c, 0o600)
		res := r.exec(t)
		want(t, res, map[string]string{"A": "file", "B": "file", "D": ""})
		if !strings.Contains(res.stderr, "ignoring the cached snapshot") && name != "empty" {
			t.Errorf("%s: log %q", name, res.stderr)
		}
		if !strings.Contains(res.stderr, "starting with env files and defaults") {
			t.Errorf("%s: log %q", name, res.stderr)
		}
	}

	// A cache sealed for another app, put under this app's name, is refused too.
	os.WriteFile(r.cache, good, 0o600)
	r.env["VUKA_CONFIG_TOKEN"] = "someone-elses-token"
	if res := r.exec(t); res.env["A"] != "file" {
		t.Errorf("a cache opened with another token: %v", res.env)
	}
}

func TestNoCacheStartsWithoutAndSaysSo(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	r := newRun(t, s)
	s.Close()
	res := r.exec(t)
	want(t, res, map[string]string{"A": "file", "B": "file", "C": "file", "D": "", "REAL": "real"})
	if !strings.Contains(res.stderr, "error") || !strings.Contains(res.stderr, "127.0.0.1") || !strings.Contains(res.stderr, "env files and defaults") {
		t.Errorf("log: %q", res.stderr)
	}
	checkLogs(t, res)
}

func TestFailFast(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	r := newRun(t, s)
	r.env["VUKA_CONFIG_FAIL_FAST"] = "1"
	if res := r.exec(t); res.code != 0 || res.env["A"] != "server-shared" {
		t.Fatalf("with the server up: %d %v %s", res.code, res.env, res.stderr)
	}
	s.Close()
	res := r.exec(t) // a cache exists, but the snapshot isn't fresh
	if res.code == 0 || !strings.Contains(res.stderr, "127.0.0.1") || !strings.Contains(res.stderr, "no fresh snapshot") {
		t.Errorf("with the server down: code %d, log %q", res.code, res.stderr)
	}
	checkLogs(t, res)
	r.env["VUKA_CONFIG_KEY"] = "-"
	if res := r.exec(t); res.code == 0 {
		t.Error("a missing key started")
	}
}

func TestRetriesThenSucceeds(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	s := newServer(t, served, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) <= 2 {
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
	res := newRun(t, s).exec(t)
	want(t, res, map[string]string{"A": "server-shared"})
	if n.Load() != 3 {
		t.Errorf("%d requests", n.Load())
	}
}

func TestRefusedIsNotRetried(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	r := newRun(t, s)
	r.env["VUKA_CONFIG_TOKEN"] = "wrong"
	res := r.exec(t)
	want(t, res, map[string]string{"A": "file"})
	if s.hits.Load() != 1 || !strings.Contains(res.stderr, "401") {
		t.Errorf("hits %d, log %q", s.hits.Load(), res.stderr)
	}
}

func TestTamperedResponseRejected(t *testing.T) {
	t.Parallel()
	for name, wrap := range map[string]func(http.Handler) http.Handler{
		"value changed on the path": func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				w.Write(bytes.Replace(rec.Body.Bytes(), []byte("server-shared"), []byte("evil-shared!"), 1))
			})
		},
		"another app's snapshot": func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				w.Write(bytes.Replace(rec.Body.Bytes(), []byte(`"app":"orders"`), []byte(`"app":"billing"`), 1))
			})
		},
	} {
		s := newServer(t, served, wrap)
		res := newRun(t, s).exec(t)
		want(t, res, map[string]string{"A": "file", "B": "file", "D": ""})
		if !strings.Contains(res.stderr, "signature") {
			t.Errorf("%s: log %q", name, res.stderr)
		}
	}
	// A server signing with a key the client wasn't given.
	s := newServer(t, served, nil)
	r := newRun(t, s)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	r.env["VUKA_CONFIG_KEY"] = base64.StdEncoding.EncodeToString(pub)
	if res := r.exec(t); res.env["A"] != "file" {
		t.Errorf("an unknown signer was trusted: %v", res.env)
	}
}

func TestSnapshotForAnotherLabelRefused(t *testing.T) {
	t.Parallel()
	s := newServer(t, served, nil)
	r := newRun(t, s)
	r.env["VUKA_CONFIG_LABEL"] = "v42" // a directory source has no labels
	res := r.exec(t)
	want(t, res, map[string]string{"A": "file"})
	if !strings.Contains(res.stderr, "404") {
		t.Errorf("log %q", res.stderr)
	}
}

func TestNoProfile(t *testing.T) {
	t.Parallel()
	s := newServer(t, map[string]string{"orders/.env": "A=from-app-env\nSHARED=app\n", ".env": "SHARED=root\nONLY=root\n", ".env.default": "A=no\n", "orders/.env.production": "A=no\n"}, nil)
	r := newRun(t, s)
	r.env["VUKA_ENV"] = "-"
	r.env["CLIENT_PROBE"] = "A,SHARED,ONLY"
	res := r.exec(t)
	want(t, res, map[string]string{"A": "from-app-env", "SHARED": "app", "ONLY": "root"})
}
