package config_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/config/v2/source/dirsrc"
	"github.com/vuka-lang/config/v2/source/gitsrc"
)

type fixture struct {
	srv     *httptest.Server
	handler *config.Handler
	pub     ed25519.PublicKey
	tokens  map[string]string
	dir     string
}

func newFixture(t *testing.T, cfg func(*config.ServerConfig)) *fixture {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		".env":                          "MAIL_HOST=smtp.internal\nLOG=info\n",
		".env.production":               "LOG=warn\n",
		"orders/.env":                   "ORDERS_DB=orders-db\n",
		"orders/.env.production":        "RATE=100\nSECRET_ORDERS=$$\n",
		".env.local":                    "ROOT_LOCAL=1\n",
		".env.staging.local":            "X=1\n",
		".git/.env":                     "GIT_DIR=1\n",
		"order-service/.env":            "OS=1\n",
		"order-service/.env.production": "OSP=1\n",
		"billing/.env":                  "BILLING_KEY=billing-only\n",
		"billing/.env.production":       "BILLING_PROD=1\n",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	src, err := dirsrc.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{pub: pub, dir: dir, tokens: map[string]string{"orders": config.NewToken(), "billing": config.NewToken(), "order-service": config.NewToken()}}
	c := config.ServerConfig{Source: src, Key: priv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Tokens: map[string]string{}}
	for app, tok := range f.tokens {
		c.Tokens[app] = config.HashToken(tok)
	}
	if cfg != nil {
		cfg(&c)
	}
	h, err := config.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	f.handler = h
	f.srv = httptest.NewServer(h)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) get(t *testing.T, path, token string) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", f.srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, body
}

func TestServerJSON(t *testing.T) {
	f := newFixture(t, nil)
	code, hdr, body := f.get(t, "/orders/production", f.tokens["orders"])
	if code != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", code, hdr)
	}
	snap, err := config.Verify(body, f.pub)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"MAIL_HOST": "smtp.internal", "LOG": "warn", "ORDERS_DB": "orders-db", "RATE": "100", "SECRET_ORDERS": "$$"}
	if snap.App != "orders" || snap.Profile != "production" || len(snap.Values) != len(want) || snap.Version == "" || hdr.Get("X-Config-Version") != snap.Version {
		t.Errorf("%+v", snap)
	}
	for k, v := range want {
		if snap.Values[k] != v {
			t.Errorf("%s = %q, want %q", k, snap.Values[k], v)
		}
	}
	var files []string
	for _, s := range snap.Sources {
		files = append(files, s.File)
	}
	if strings.Join(files, " ") != ".env .env.production orders/.env orders/.env.production" || snap.Sources[1].Values["LOG"] != "warn" || snap.Sources[0].Version == "" {
		t.Errorf("sources: %+v", snap.Sources)
	}
	var shape map[string]json.RawMessage
	json.Unmarshal(body, &shape)
	for _, k := range []string{"app", "profile", "label", "version", "sources", "values", "signature"} {
		if _, ok := shape[k]; !ok {
			t.Errorf("no %q member", k)
		}
	}
	// Another profile: a missing file is fine.
	code, _, body = f.get(t, "/orders/staging", f.tokens["orders"])
	snap, err = config.Verify(body, f.pub)
	if code != 200 || err != nil || len(snap.Sources) != 2 || snap.Values["LOG"] != "info" {
		t.Errorf("staging: %d %+v %v", code, snap, err)
	}
}

func TestServerEnv(t *testing.T) {
	f := newFixture(t, nil)
	code, hdr, body := f.get(t, "/orders/production.env", f.tokens["orders"])
	if code != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/plain") {
		t.Fatalf("%d %v", code, hdr)
	}
	if want := "LOG=\"warn\"\nMAIL_HOST=\"smtp.internal\"\nORDERS_DB=\"orders-db\"\nRATE=\"100\"\nSECRET_ORDERS=\"\\$\\$\"\n"; string(body) != want {
		t.Errorf("%s", body)
	}
	pairs, err := config.ParseEnv("x", body, nil, nil)
	if err != nil || len(pairs) != 5 {
		t.Errorf("the .env output reads back: %v %v", pairs, err)
	}
	if !config.VerifyEnv(f.pub, body, hdr.Get("X-Config-Signature")) {
		t.Error("env signature")
	}
	if config.VerifyEnv(f.pub, append(body, '\n'), hdr.Get("X-Config-Signature")) {
		t.Error("tampered env verified")
	}
	if code, _, _ := f.get(t, "/orders/production/main.env", f.tokens["orders"]); code != 404 {
		t.Errorf("a label on a directory source: %d", code)
	}
}

func TestServerTokenScoping(t *testing.T) {
	f := newFixture(t, nil)
	_, _, body := f.get(t, "/orders/production", f.tokens["orders"])
	if strings.Contains(string(body), "ROOT_LOCAL") || strings.Contains(string(body), "GIT_DIR") || strings.Contains(string(body), `"OS":`) {
		t.Error("orders' snapshot holds a file outside its four paths")
	}
	if strings.Contains(string(body), "billing") || strings.Contains(string(body), "BILLING") {
		t.Error("orders' snapshot holds billing's values")
	}
	_, _, body = f.get(t, "/billing/production", f.tokens["billing"])
	snap, err := config.Verify(body, f.pub)
	if err != nil || snap.Values["BILLING_KEY"] != "billing-only" || snap.Values["MAIL_HOST"] != "smtp.internal" || snap.Values["ORDERS_DB"] != "" {
		t.Errorf("billing: %+v %v", snap, err)
	}

	// 404 for another app's name, an unknown app and a reserved one alike.
	var bodies []string
	for _, path := range []string{"/billing/production", "/billing/production.env", "/nobody/production", "/application/production", "/application-production/x", "/_hooks/production"} {
		code, _, b := f.get(t, path, f.tokens["orders"])
		if code != 404 {
			t.Errorf("%s with orders' token: %d", path, code)
		}
		bodies = append(bodies, string(b))
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Error("404 bodies differ")
		}
	}
	// Without a valid token nothing is learned about any app.
	for _, tok := range []string{"", "wrong", f.tokens["orders"] + "x"} {
		for _, path := range []string{"/orders/production", "/billing/production", "/nobody/production"} {
			if code, hdr, _ := f.get(t, path, tok); code != 401 || hdr.Get("WWW-Authenticate") == "" {
				t.Errorf("%s with token %q: %d", path, tok, code)
			}
		}
	}
	req, _ := http.NewRequest("POST", f.srv.URL+"/orders/production", nil)
	req.Header.Set("Authorization", "Bearer "+f.tokens["orders"])
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 405 {
		t.Errorf("POST: %d", resp.StatusCode)
	}
}

func TestServerBadNames(t *testing.T) {
	f := newFixture(t, nil)
	tok := f.tokens["orders"]
	for _, path := range []string{
		"/orders", "/orders/production/a/b", "/orders/..", "/orders/%2e%2e/x", "/orders/pro%2Fduction", "/orders/prod uction",
		"/orders/production/--upload-pack=x", "/orders/production/..%2Fx", "/orders/-x", "/",
	} {
		if code, _, _ := f.get(t, path, tok); code != 404 {
			t.Errorf("%s: %d", path, code)
		}
	}
}

func TestServerNeverLogsTokens(t *testing.T) {
	var logs strings.Builder
	f := newFixture(t, func(c *config.ServerConfig) {
		c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		c.Source = failing{}
	})
	tok := f.tokens["orders"]
	if code, _, _ := f.get(t, "/orders/production", tok); code != 502 {
		t.Fatalf("%d", code)
	}
	if logs.Len() == 0 || strings.Contains(logs.String(), tok) || strings.Contains(logs.String(), config.HashToken(tok)) {
		t.Errorf("logs: %q", logs.String())
	}
}

type failing struct{}

func (failing) Read(context.Context, string, []string) (config.Tree, error) {
	return config.Tree{}, io.ErrUnexpectedEOF
}

func TestServerSignaturesBindTheRequest(t *testing.T) {
	f := newFixture(t, nil)
	_, _, body := f.get(t, "/orders/production", f.tokens["orders"])
	forged := strings.Replace(string(body), `"profile":"production"`, `"profile":"staging"`, 1)
	if _, err := config.Verify([]byte(forged), f.pub); err == nil {
		t.Error("a snapshot replayed as another profile verifies")
	}
}

type fakeRefresher struct {
	config.Source
	mu sync.Mutex
	n  int
}

func (r *fakeRefresher) Refresh(context.Context) error { r.mu.Lock(); r.n++; r.mu.Unlock(); return nil }

func TestServerHook(t *testing.T) {
	var ref *fakeRefresher
	f := newFixture(t, func(c *config.ServerConfig) {
		ref = &fakeRefresher{Source: c.Source}
		c.Source, c.HookSecret = ref, "s3cret"
	})
	post := func(hdr map[string]string, body string) int {
		req, _ := http.NewRequest("POST", f.srv.URL+"/_hooks/git", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte("{}"))
	badMac := hmac.New(sha256.New, []byte("other"))
	badMac.Write([]byte("{}"))
	for name, c := range map[string]struct {
		hdr  map[string]string
		body string
		want int
	}{
		"no secret":         {nil, "{}", 403},
		"wrong token":       {map[string]string{"X-Hook-Token": "nope"}, "{}", 403},
		"prefix of secret":  {map[string]string{"X-Hook-Token": "s3cre"}, "{}", 403},
		"token":             {map[string]string{"X-Hook-Token": "s3cret"}, "{}", 204},
		"gitlab token":      {map[string]string{"X-Gitlab-Token": "s3cret"}, "{}", 204},
		"hmac":              {map[string]string{"X-Hub-Signature-256": "sha256=" + hex.EncodeToString(mac.Sum(nil))}, "{}", 204},
		"hmac, other body":  {map[string]string{"X-Hub-Signature-256": "sha256=" + hex.EncodeToString(mac.Sum(nil))}, "{ }", 403},
		"hmac, wrong key":   {map[string]string{"X-Hub-Signature-256": "sha256=" + hex.EncodeToString(badMac.Sum(nil))}, "{}", 403},
		"hmac, not hex":     {map[string]string{"X-Hub-Signature-256": "sha256=zz"}, "{}", 403},
		"api token as hook": {map[string]string{"X-Hook-Token": f.tokens["orders"]}, "{}", 403},
	} {
		if got := post(c.hdr, c.body); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	if ref.n != 3 {
		t.Errorf("%d refreshes, want 3", ref.n)
	}
	if code, _, _ := f.get(t, "/_hooks/git", f.tokens["orders"]); code != 404 {
		t.Errorf("GET hook: %d", code)
	}
}

func TestServerHookDisabled(t *testing.T) {
	f := newFixture(t, nil) // no HookSecret, and a Source that can't refresh
	resp, err := http.Post(f.srv.URL+"/_hooks/git", "application/json", strings.NewReader("{}"))
	if err != nil || resp.StatusCode != 404 {
		t.Errorf("%v %v", resp, err)
	}
}

func TestServerGitHookAndLabels(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
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
	git("tag", "v1")
	src, err := gitsrc.Open(context.Background(), gitsrc.Options{URL: repo, Dir: filepath.Join(t.TempDir(), "m")})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(c *config.ServerConfig) { c.Source, c.HookSecret = src, "hook" })
	value := func(path string) (string, string, int) {
		code, _, body := f.get(t, path, f.tokens["orders"])
		snap, err := config.Verify(body, f.pub)
		if err != nil {
			return "", "", code
		}
		return snap.Values["A"], snap.Label, code
	}
	if a, label, _ := value("/orders/production"); a != "1" || label != "main" {
		t.Fatalf("%q %q", a, label)
	}
	commit("A=2\n")
	if a, _, _ := value("/orders/production"); a != "1" {
		t.Errorf("served a commit nothing fetched: %q", a)
	}
	req, _ := http.NewRequest("POST", f.srv.URL+"/_hooks/git", nil)
	req.Header.Set("X-Hook-Token", "hook")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 204 {
		t.Fatalf("hook: %v %v", resp, err)
	}
	if a, _, _ := value("/orders/production"); a != "2" {
		t.Errorf("after the hook: %q", a)
	}
	if a, label, _ := value("/orders/production/v1"); a != "1" || label != "v1" {
		t.Errorf("pinned to v1: %q %q", a, label)
	}
	if _, _, code := value("/orders/production/nope"); code != 404 {
		t.Errorf("unknown label: %d", code)
	}
	if _, _, code := value("/orders/production/--upload-pack=x"); code != 404 {
		t.Errorf("hostile label: %d", code)
	}
}

func TestParseTokens(t *testing.T) {
	h := config.HashToken("x")
	got, err := config.ParseTokens("# tokens\norders=" + h + " # inline\n\nbilling=" + h + ", order-service=" + h + "\n")
	if err != nil || len(got) != 3 || got["order-service"] != h {
		t.Errorf("%v %v", got, err)
	}
	for _, bad := range []string{"orders", "orders=zz", "orders=" + h[:10], "bad/app=" + h, "-x=" + h, ".git=" + h, "_hooks=" + h, "a b=" + h} {
		if _, err := config.ParseTokens(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := config.Server(config.ServerConfig{}); err == nil {
		t.Error("Server without a source")
	}
}

func TestServerHyphenatedAppsAndNoProfile(t *testing.T) {
	f := newFixture(t, nil)
	_, _, body := f.get(t, "/order-service/production", f.tokens["order-service"])
	snap, err := config.Verify(body, f.pub)
	if err != nil || snap.Values["OS"] != "1" || snap.Values["OSP"] != "1" || snap.Values["MAIL_HOST"] != "smtp.internal" || snap.Values["ORDERS_DB"] != "" {
		t.Errorf("%+v %v", snap, err)
	}
	// No profile: only the two .env files apply.
	_, _, body = f.get(t, "/orders/"+config.NoProfile, f.tokens["orders"])
	snap, err = config.Verify(body, f.pub)
	if err != nil || snap.Profile != "" || len(snap.Sources) != 2 || snap.Values["MAIL_HOST"] != "smtp.internal" || snap.Values["RATE"] != "" || snap.Values["LOG"] != "info" {
		t.Errorf("%+v %v", snap, err)
	}
	if code, _, _ := f.get(t, "/order/production", f.tokens["order-service"]); code != 404 {
		t.Errorf("a prefix of an app's name: %d", code)
	}
	for _, path := range []string{"/.git/production", "/../production", "/-x/production", "/a%2Fb/production", "/%2e%2e/x", "/_hooks/production"} {
		if code, _, _ := f.get(t, path, f.tokens["orders"]); code != 404 {
			t.Errorf("%s: %d", path, code)
		}
	}
}
