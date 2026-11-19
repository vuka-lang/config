package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/config/v2/client"
	"github.com/vuka-lang/config/v2/source/dirsrc"
	"github.com/vuka-lang/web/v2"
)

// These tests run the client in the test process, so they share web's
// environment and its "config" source: none of them is parallel.

type live struct {
	dir, pub, addr string
	h              *config.Handler
	srv            *httptest.Server
	hook           atomic.Pointer[func(http.ResponseWriter, *http.Request) bool]
	watches        atomic.Int32
	requests       atomic.Int32
}

func newLive(t *testing.T, files map[string]string) *live {
	t.Helper()
	l := &live{dir: t.TempDir()}
	for name, body := range files {
		l.write(name, body)
	}
	src, _ := dirsrc.New(l.dir)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l.pub = base64.StdEncoding.EncodeToString(pub)
	h, err := config.Server(config.ServerConfig{
		Source: src, Key: priv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tokens:        map[string]string{"orders": config.HashToken(token)},
		WatchInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	l.h = h
	l.start(t)
	t.Cleanup(l.stop)
	return l
}

func (l *live) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.requests.Add(1)
		if strings.HasSuffix(r.URL.Path, "/watch") {
			l.watches.Add(1)
		}
		if f := l.hook.Load(); f != nil && (*f)(w, r) {
			return
		}
		l.h.ServeHTTP(w, r)
	})
}

func (l *live) start(t *testing.T) {
	t.Helper()
	l.srv = httptest.NewUnstartedServer(l.handler())
	if l.addr != "" {
		var ln net.Listener
		var err error
		for range 50 {
			if ln, err = net.Listen("tcp", l.addr); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		l.srv.Listener.Close()
		l.srv.Listener = ln
	}
	l.srv.Start()
	l.addr = l.srv.Listener.Addr().String()
}

// stop closes the streams, then the listener; start brings it back on the
// same address with the same handler state.
func (l *live) stop() {
	if l.srv == nil {
		return
	}
	l.h.Close()
	l.srv.Close()
	l.srv = nil
}

func (l *live) restart(t *testing.T) {
	t.Helper()
	l.stop()
	h, err := config.Server(l.h.ServerConfig)
	if err != nil {
		t.Fatal(err)
	}
	l.h = h
	l.start(t)
}

func (l *live) write(name, body string) {
	os.MkdirAll(filepath.Dir(filepath.Join(l.dir, name)), 0o755)
	os.WriteFile(filepath.Join(l.dir, name), []byte(body), 0o644)
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func captureLog(t *testing.T) *logBuf {
	t.Helper()
	b := &logBuf{}
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return b
}

func (l *live) config(t *testing.T) client.Config {
	return client.Config{
		URI: l.srv.URL, Token: token, App: "orders", Profile: "production", Key: l.pub,
		Cache: filepath.Join(t.TempDir(), "orders.snapshot"), Backoff: []time.Duration{},
		Timeout: 2 * time.Second, Poll: time.Hour, Reconnect: 20 * time.Millisecond,
	}
}

func open(t *testing.T, c client.Config) *client.Client {
	t.Helper()
	cl, err := client.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cl.Stop()
		web.ApplyEnv("config", nil)
	})
	return cl
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func steady(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if !ok() {
			t.Fatalf("%s", what)
		}
	}
}

func env(k string) func() string { return func() string { return os.Getenv(k) } }

func is(f func() string, want string) func() bool { return func() bool { return f() == want } }

func noValues(t *testing.T, logs *logBuf, values ...string) {
	t.Helper()
	for _, v := range append(values, token) {
		if strings.Contains(logs.String(), v) {
			t.Errorf("the log holds %q:\n%s", v, logs.String())
		}
	}
}

func TestFollowAppliesChangesFromTheStream(t *testing.T) {
	logs := captureLog(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".env")
	os.WriteFile(file, []byte("FL1_FILE=from-file\nFL1_TOFILE=file-value\n"), 0o644)
	if err := web.LoadEnv(file); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FL1_REAL", "real")
	l := newLive(t, map[string]string{
		"orders/.env.production": "FL1_A=one-secretish\nFL1_N=5\nFL1_GONE=gone-secretish\nFL1_TOFILE=server-value\nFL1_REAL=server\nVUKA_EVIL=1\n",
	})
	open(t, l.config(t)) // Poll is an hour: only the stream can deliver the change
	hot := web.Hot[int]("FL1_N", 1)
	var called atomic.Value
	unregister := web.OnEnvChange("FL1_A", func(old, new string) { called.Store(old + ">" + new) })
	defer unregister()
	if web.Env[string]("FL1_A") != "one-secretish" || hot.Get() != 5 || os.Getenv("FL1_TOFILE") != "server-value" || os.Getenv("FL1_REAL") != "real" {
		t.Fatalf("start: %q %d %q %q", os.Getenv("FL1_A"), hot.Get(), os.Getenv("FL1_TOFILE"), os.Getenv("FL1_REAL"))
	}
	if os.Getenv("VUKA_EVIL") != "" {
		t.Error("a reserved key was applied")
	}

	l.write("orders/.env.production", "FL1_A=two-secretish\nFL1_N=9\nFL1_REAL=server2\nFL1_NEW=new-secretish\nVUKA_EVIL=2\n")
	eventually(t, "the new value", is(env("FL1_A"), "two-secretish"))
	if got := web.Env[string]("FL1_A"); got != "two-secretish" {
		t.Errorf("web.Env: %q", got)
	}
	if got := hot.Get(); got != 9 {
		t.Errorf("Hot: %d", got)
	}
	if got, _ := called.Load().(string); got != "one-secretish>two-secretish" {
		t.Errorf("OnEnvChange: %q", got)
	}
	if v, set := os.LookupEnv("FL1_GONE"); set {
		t.Errorf("a key removed from the source is still set: %q", v)
	}
	if got := os.Getenv("FL1_TOFILE"); got != "file-value" {
		t.Errorf("a removed key did not go back to the env file's value: %q", got)
	}
	if os.Getenv("FL1_REAL") != "real" || os.Getenv("FL1_FILE") != "from-file" || os.Getenv("VUKA_EVIL") != "" {
		t.Errorf("real %q file %q evil %q", os.Getenv("FL1_REAL"), os.Getenv("FL1_FILE"), os.Getenv("VUKA_EVIL"))
	}
	if l.watches.Load() == 0 {
		t.Error("the client never opened the stream")
	}
	log := logs.String()
	if !strings.Contains(log, "config: applied ") || !strings.Contains(log, "FL1_A") || !strings.Contains(log, "FL1_GONE") || !strings.Contains(log, "version") {
		t.Errorf("log: %q", log)
	}
	noValues(t, logs, "one-secretish", "two-secretish", "gone-secretish", "new-secretish", "server-value", "file-value")
}

func TestFollowPollWhenTheStreamIsCut(t *testing.T) {
	logs := captureLog(t)
	l := newLive(t, map[string]string{"orders/.env.production": "FL2_A=one\n"})
	cut := func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/watch") {
			http.Error(w, "no streams today", http.StatusServiceUnavailable)
			return true
		}
		return false
	}
	l.hook.Store(&cut)
	c := l.config(t)
	c.Poll = 50 * time.Millisecond
	open(t, c)
	l.write("orders/.env.production", "FL2_A=two\n")
	eventually(t, "the polled change", is(env("FL2_A"), "two"))
	noValues(t, logs)
}

func TestFollowReconnectsAfterTheServerRestarts(t *testing.T) {
	logs := captureLog(t)
	l := newLive(t, map[string]string{"orders/.env.production": "FL3_A=one\n"})
	open(t, l.config(t)) // Poll is an hour: only a reconnected stream can deliver the change
	eventually(t, "the first stream", func() bool { return l.watches.Load() > 0 })
	before := l.watches.Load()

	l.stop()
	l.write("orders/.env.production", "FL3_A=two\n")
	steady(t, "a value changed with the server down", 150*time.Millisecond, func() bool { return os.Getenv("FL3_A") == "one" })
	l.restart(t)
	eventually(t, "the change after the restart", is(env("FL3_A"), "two"))
	if l.watches.Load() <= before {
		t.Error("the stream did not reconnect")
	}
	l.write("orders/.env.production", "FL3_A=three\n")
	eventually(t, "a change on the new stream", is(env("FL3_A"), "three"))
	noValues(t, logs)
}

func TestFollowRefusesUpdatesThatDoNotVerify(t *testing.T) {
	logs := captureLog(t)
	l := newLive(t, map[string]string{"orders/.env.production": "FL4_A=good\n"})
	var mode atomic.Value
	mode.Store("")
	sigRe := regexp.MustCompile(`"signature":"[^"]*"`)
	bad := func(w http.ResponseWriter, r *http.Request) bool {
		m, _ := mode.Load().(string)
		if m == "" || strings.HasSuffix(r.URL.Path, "/watch") || r.Method == http.MethodHead {
			return false
		}
		rec := httptest.NewRecorder()
		l.h.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		switch m {
		case "tampered":
			body = bytes.Replace(body, []byte("changed-value"), []byte("evil-value!!"), 1)
		case "unsigned":
			body = sigRe.ReplaceAll(body, nil)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Write(body)
		return true
	}
	l.hook.Store(&bad)
	c := l.config(t)
	c.Poll = 30 * time.Millisecond
	open(t, c)

	for _, m := range []string{"tampered", "unsigned"} {
		mode.Store(m)
		l.write("orders/.env.production", "FL4_A=changed-value\n")
		steady(t, m+": an update that does not verify was applied", 300*time.Millisecond, func() bool { return os.Getenv("FL4_A") == "good" })
		mode.Store("")
		eventually(t, "the genuine update", is(env("FL4_A"), "changed-value"))
		l.write("orders/.env.production", "FL4_A=good\n")
		eventually(t, "back", is(env("FL4_A"), "good"))
	}
	if !strings.Contains(logs.String(), "signature") || !strings.Contains(logs.String(), "127.0.0.1") {
		t.Errorf("log: %q", logs.String())
	}
	noValues(t, logs, "good", "changed-value", "evil-value")
}

func TestFollowRefusesWhatItCannotDecrypt(t *testing.T) {
	logs := captureLog(t)
	mine, other := mkKey(t), mkKey(t)
	l := newLive(t, map[string]string{
		"orders/.env.production": "FL5_PLAIN=before\nFL5_PW=" + seal(t, mine, "orders", "FL5_PW", "pw-one-secret") + "\n",
	})
	c := l.config(t)
	c.SecretKeys = mine.String()
	open(t, c)
	if os.Getenv("FL5_PW") != "pw-one-secret" || os.Getenv("FL5_PLAIN") != "before" {
		t.Fatalf("start: %q %q", os.Getenv("FL5_PW"), os.Getenv("FL5_PLAIN"))
	}

	foreign := seal(t, other, "orders", "FL5_PW", "pw-two-secret")
	moved := seal(t, mine, "orders", "FL5_OTHER", "pw-three-secret")
	for name, body := range map[string]string{
		"another key":      "FL5_PLAIN=after\nFL5_PW=" + foreign + "\n",
		"another variable": "FL5_PLAIN=after\nFL5_PW=" + moved + "\n",
	} {
		l.write("orders/.env.production", body)
		steady(t, name+": applied", 300*time.Millisecond, func() bool {
			return os.Getenv("FL5_PW") == "pw-one-secret" && os.Getenv("FL5_PLAIN") == "before"
		})
	}
	log := logs.String()
	if !strings.Contains(log, "FL5_PW") || !strings.Contains(log, "cannot decrypt") || !strings.Contains(log, "not applying") {
		t.Errorf("log: %q", log)
	}
	if n := strings.Count(log, "not applying"); n != 2 {
		t.Errorf("%d reports for 2 refused versions:\n%s", n, log)
	}

	l.write("orders/.env.production", "FL5_PLAIN=after\nFL5_PW="+seal(t, mine, "orders", "FL5_PW", "pw-four-secret")+"\n")
	eventually(t, "the decryptable update", is(env("FL5_PW"), "pw-four-secret"))
	if os.Getenv("FL5_PLAIN") != "after" {
		t.Error("the plain value of the same update was not applied")
	}
	noValues(t, logs, "pw-one-secret", "pw-two-secret", "pw-three-secret", "pw-four-secret", foreign, moved, plainSecret)
}

func TestFollowOff(t *testing.T) {
	l := newLive(t, map[string]string{"orders/.env.production": "FL6_A=one\n"})
	c := l.config(t)
	c.NoWatch, c.Poll = true, 30*time.Millisecond
	open(t, c)
	l.write("orders/.env.production", "FL6_A=two\n")
	steady(t, "a client that does not follow changed", 400*time.Millisecond, func() bool { return os.Getenv("FL6_A") == "one" })
	if n := l.requests.Load(); n != 1 {
		t.Errorf("%d requests, want the start-up fetch only", n)
	}
	t.Setenv("VUKA_CONFIG_WATCH", "0")
	if !client.FromEnv().NoWatch {
		t.Error("VUKA_CONFIG_WATCH=0 does not turn following off")
	}
	t.Setenv("VUKA_CONFIG_WATCH", "")
	if client.FromEnv().NoWatch {
		t.Error("following is off by default")
	}
}

func TestFollowStartedWithTheServerDown(t *testing.T) {
	logs := captureLog(t)
	t.Setenv("FL7_REAL", "real")
	l := newLive(t, map[string]string{"orders/.env.production": "FL7_A=from-server\nFL7_REAL=server\n"})
	c := l.config(t)
	l.stop()
	open(t, c)
	if os.Getenv("FL7_A") != "" {
		t.Fatal("applied with no server")
	}
	if !strings.Contains(logs.String(), "starting with env files and defaults") {
		t.Errorf("log: %q", logs.String())
	}
	l.restart(t)
	eventually(t, "the first snapshot", is(env("FL7_A"), "from-server"))
	if os.Getenv("FL7_REAL") != "real" {
		t.Error("the real environment lost")
	}
	noValues(t, logs, "from-server")
}

func TestFollowUpdatesTheCache(t *testing.T) {
	logs := captureLog(t)
	l := newLive(t, map[string]string{"orders/.env.production": "FL8_A=one\n"})
	c := l.config(t)
	cl := open(t, c)
	l.write("orders/.env.production", "FL8_A=two\n")
	eventually(t, "the change", is(env("FL8_A"), "two"))
	cl.Stop()
	web.ApplyEnv("config", nil)
	if os.Getenv("FL8_A") != "" {
		t.Fatal("not reverted")
	}
	l.stop()
	c.NoWatch = true
	open(t, c)
	if got := os.Getenv("FL8_A"); got != "two" {
		t.Errorf("the cache holds %q, want the last update", got)
	}
	noValues(t, logs)
}

func TestStopEndsFollowing(t *testing.T) {
	l := newLive(t, map[string]string{"orders/.env.production": "FL9_A=one\n"})
	cl := open(t, l.config(t))
	eventually(t, "the stream", func() bool { return l.watches.Load() > 0 })
	cl.Stop()
	cl.Stop()
	l.write("orders/.env.production", "FL9_A=two\n")
	steady(t, "a stopped client applied a change", 300*time.Millisecond, func() bool { return os.Getenv("FL9_A") == "one" })
}
