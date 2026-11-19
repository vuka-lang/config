package config_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/config/v2/source/dirsrc"
	"github.com/vuka-lang/config/v2/source/gitsrc"
)

func key(t *testing.T) *config.SecretKey {
	t.Helper()
	k, err := config.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func enc(t *testing.T, k *config.SecretKey, app, name, value string) string {
	t.Helper()
	v, err := config.Encrypt(k.Public(), app, name, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCipherRoundTripAndFormat(t *testing.T) {
	k := key(t)
	v := enc(t, k, "orders", "DB_PASSWORD", "hunter2")
	if !strings.HasPrefix(v, "{cipher}v1:"+k.ID()+":") || strings.Contains(v, "hunter2") {
		t.Fatalf("format: %q", v)
	}
	if v2 := enc(t, k, "orders", "DB_PASSWORD", "hunter2"); v2 == v {
		t.Error("two encryptions of one value are equal")
	}
	got, err := config.Decrypt([]*config.SecretKey{k}, "orders", "DB_PASSWORD", v)
	if err != nil || got != "hunter2" {
		t.Fatalf("%q %v", got, err)
	}
	if id, err := config.CipherKeyID(v); err != nil || id != k.ID() {
		t.Errorf("%q %v", id, err)
	}
	k2, err := config.ParseSecretKey(k.String())
	if err != nil || k2.ID() != k.ID() {
		t.Fatalf("%v", err)
	}
	if got, err := config.Decrypt([]*config.SecretKey{k2}, "orders", "DB_PASSWORD", v); err != nil || got != "hunter2" {
		t.Errorf("a parsed key: %q %v", got, err)
	}
	pub, err := config.ParseSecretPublicKey(k.Public().String())
	if err != nil || pub.ID() != k.ID() {
		t.Errorf("%v", err)
	}
}

func TestCipherIsBoundToAppAndVariable(t *testing.T) {
	k := key(t)
	keys := []*config.SecretKey{k}
	v := enc(t, k, "orders", "DB_PASSWORD", "hunter2")
	if _, err := config.Decrypt(keys, "billing", "DB_PASSWORD", v); !errors.Is(err, config.ErrDecrypt) {
		t.Errorf("another app: %v", err)
	}
	if _, err := config.Decrypt(keys, "orders", "API_KEY", v); !errors.Is(err, config.ErrDecrypt) {
		t.Errorf("another variable: %v", err)
	}
	if _, err := config.Decrypt(keys, "order", "sDB_PASSWORD", v); !errors.Is(err, config.ErrDecrypt) {
		t.Errorf("shifted boundary: %v", err)
	}
}

func TestCipherFailures(t *testing.T) {
	k, other := key(t), key(t)
	v := enc(t, k, "orders", "X", "hunter2")
	flip := func(i int) string {
		b := []byte(v)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	prefix := len("{cipher}v1:" + k.ID() + ":")
	for name, c := range map[string]struct {
		keys []*config.SecretKey
		v    string
		want error
	}{
		"wrong key":      {[]*config.SecretKey{other}, v, config.ErrNoKey},
		"no keys":        {nil, v, config.ErrNoKey},
		"tampered enc":   {[]*config.SecretKey{k}, flip(prefix + 3), config.ErrDecrypt},
		"tampered body":  {[]*config.SecretKey{k}, flip(len(v) - 5), config.ErrDecrypt},
		"truncated":      {[]*config.SecretKey{k}, v[:len(v)-6], config.ErrDecrypt},
		"short":          {[]*config.SecretKey{k}, "{cipher}v1:" + k.ID() + ":AAAA", config.ErrMalformed},
		"bad version":    {[]*config.SecretKey{k}, strings.Replace(v, "v1", "v2", 1), config.ErrMalformed},
		"no id":          {[]*config.SecretKey{k}, "{cipher}v1:" + v[prefix:], config.ErrMalformed},
		"not base64":     {[]*config.SecretKey{k}, "{cipher}v1:" + k.ID() + ":!!!!", config.ErrMalformed},
		"plain":          {[]*config.SecretKey{k}, "hunter2", config.ErrMalformed},
		"swapped key id": {[]*config.SecretKey{other}, strings.Replace(v, k.ID(), other.ID(), 1), config.ErrDecrypt},
	} {
		got, err := config.Decrypt(c.keys, "orders", "X", c.v)
		if !errors.Is(err, c.want) || got != "" {
			t.Errorf("%s: %q %v, want %v", name, got, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error holds the value", name)
		}
	}
}

func TestCipherRotation(t *testing.T) {
	old, cur := key(t), key(t)
	vOld := enc(t, old, "orders", "A", "from-old")
	vCur := enc(t, cur, "orders", "B", "from-new")
	both, err := config.ParseSecretKeys(cur.String() + "," + old.String())
	if err != nil || len(both) != 2 {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ v, want string }{"A": {vOld, "from-old"}, "B": {vCur, "from-new"}} {
		if got, err := config.Decrypt(both, "orders", name, c.v); err != nil || got != c.want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	if _, err := config.Decrypt(both[:1], "orders", "A", vOld); !errors.Is(err, config.ErrNoKey) {
		t.Errorf("a removed key: %v", err)
	}
	if keys, err := config.ParseSecretKeys(""); err != nil || len(keys) != 0 {
		t.Errorf("empty: %v %v", keys, err)
	}
	if _, err := config.ParseSecretKeys(cur.String() + ",nope"); err == nil {
		t.Error("a bad key parsed")
	}
}

func TestParseAppKeys(t *testing.T) {
	a, b := key(t), key(t)
	m, err := config.ParseAppKeys("# keys\norders=" + a.Public().String() + "\n\nbilling = " + b.Public().String() + " # new\n")
	if err != nil || len(m) != 2 || m["orders"].ID() != a.ID() || m["billing"].ID() != b.ID() {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"orders", "orders=zz", "_keys=" + a.Public().String(), "a b=" + a.Public().String(),
		"orders=" + a.Public().String() + "\norders=" + b.Public().String(), "orders=" + a.String()[:10]} {
		if _, err := config.ParseAppKeys(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestKeyResponseVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = priv
	k := key(t)
	h, _ := config.Server(config.ServerConfig{Source: nopSource{}, Key: priv, AppKeys: map[string]*config.SecretPublicKey{"orders": k.Public()}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/_keys/orders", nil))
	var kr config.KeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &kr); err != nil || rec.Code != 200 {
		t.Fatalf("%d %v", rec.Code, err)
	}
	if got, err := config.VerifyKey(kr, config.AppSubject("orders"), pub); err != nil || got.ID() != k.ID() {
		t.Fatalf("%v", err)
	}
	if _, err := config.VerifyKey(kr, config.AppSubject("billing"), pub); err == nil {
		t.Error("a key for another app verified")
	}
	if _, err := config.VerifyKey(kr, config.ServerSubject, pub); err == nil {
		t.Error("an app key verified as the server's")
	}
	evil := key(t)
	sub := kr
	sub.Key, sub.ID = evil.Public().String(), evil.ID()
	if _, err := config.VerifyKey(sub, config.AppSubject("orders"), pub); err == nil {
		t.Error("a substituted key verified")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := config.VerifyKey(kr, config.AppSubject("orders"), other); err == nil {
		t.Error("verified with another signing key")
	}
}

type nopSource struct{}

func (nopSource) Read(context.Context, string, []string) (config.Tree, error) {
	return config.Tree{}, config.ErrNotFound
}

func TestSnapshotPrintsMasked(t *testing.T) {
	s := &config.Snapshot{App: "orders", Version: "abc", Values: map[string]string{"A": "plain-secret-ish", "B": "{cipher}v1:x:y"}}
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("snap", "snapshot", s)
	for _, out := range []string{s.String(), fmt.Sprintf("%v %+v %#v", s, s, s), logs.String()} {
		if strings.Contains(out, "plain-secret-ish") || strings.Contains(out, "{cipher}") || !strings.Contains(out, "A=***") {
			t.Errorf("printed %q", out)
		}
	}
}

func TestBuildRejectsCipherInSharedFiles(t *testing.T) {
	k := key(t)
	v := enc(t, k, "orders", "PW", "hunter2")
	for _, shared := range []string{".env", ".env.production"} {
		_, err := config.Build("orders", "production", config.Tree{Files: map[string][]byte{shared: []byte("OK=1\nPW=" + v + "\n")}})
		if !errors.Is(err, config.ErrSharedSecret) || !strings.Contains(err.Error(), shared) || !strings.Contains(err.Error(), "PW") || strings.Contains(err.Error(), v) {
			t.Errorf("%s: %v", shared, err)
		}
	}
	if _, err := config.Build("orders", "production", config.Tree{Files: map[string][]byte{"orders/.env.production": []byte("PW=" + v + "\n")}}); err != nil {
		t.Errorf("an app file: %v", err)
	}
	_, err := config.Build("orders", "", config.Tree{Files: map[string][]byte{"orders/.env": []byte("PW=" + v + "\nURL=https://u:${PW}@h\n")}})
	if err == nil || strings.Contains(err.Error(), v) || !strings.Contains(err.Error(), "URL") {
		t.Errorf("a cipher value interpolated: %v", err)
	}
}

// secretServer serves files from a directory with the given keys.
type secretServer struct {
	srv  *httptest.Server
	pub  ed25519.PublicKey
	logs *bytes.Buffer
	tok  string
}

func newSecretServer(t *testing.T, src config.Source, cfg func(*config.ServerConfig)) *secretServer {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &secretServer{pub: pub, logs: &bytes.Buffer{}, tok: config.NewToken()}
	c := config.ServerConfig{Source: src, Key: priv, Logger: slog.New(slog.NewTextHandler(s.logs, nil)),
		Tokens: map[string]string{"orders": config.HashToken(s.tok)}}
	if cfg != nil {
		cfg(&c)
	}
	h, err := config.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	s.srv = httptest.NewServer(h)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *secretServer) get(t *testing.T, path string, auth bool) (int, []byte, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", s.srv.URL+path, nil)
	if auth {
		req.Header.Set("Authorization", "Bearer "+s.tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(resp.Body)
	return resp.StatusCode, b.Bytes(), resp.Header
}

func dirOf(t *testing.T, files map[string]string) *dirsrc.Source {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	src, err := dirsrc.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func gitOf(t *testing.T, files map[string]string) *gitsrc.Source {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	for name, body := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755)
		os.WriteFile(filepath.Join(repo, name), []byte(body), 0o644)
	}
	git("add", "-A")
	git("commit", "-q", "-m", "c")
	src, err := gitsrc.Open(context.Background(), gitsrc.Options{URL: repo, Dir: filepath.Join(t.TempDir(), "m")})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestServerRefusesCipherInSharedFiles(t *testing.T) {
	k := key(t)
	v := enc(t, k, "orders", "PW", "hunter2")
	for _, shared := range []string{".env", ".env.production"} {
		files := map[string]string{shared: "PW=" + v + "\n", "orders/.env": "A=1\n"}
		for name, src := range map[string]config.Source{"dir": dirOf(t, files), "git": gitOf(t, files)} {
			s := newSecretServer(t, src, nil)
			for _, path := range []string{"/orders/production", "/orders/production.env"} {
				code, body, _ := s.get(t, path, true)
				if code != 500 || !strings.Contains(string(body), shared) || !strings.Contains(string(body), "PW") ||
					strings.Contains(string(body), v) || strings.Contains(string(body), "A=1") || strings.Contains(string(body), "signature") {
					t.Errorf("%s %s %s: %d %q", name, shared, path, code, body)
				}
			}
			if l := s.logs.String(); !strings.Contains(l, "level=ERROR") || !strings.Contains(l, shared) || strings.Contains(l, v) {
				t.Errorf("%s %s: log %q", name, shared, l)
			}
		}
	}
}

func TestServerPassesCiphertextThroughAndSigns(t *testing.T) {
	app, srvKey := key(t), key(t)
	vApp := enc(t, app, "orders", "DB_PASSWORD", "app-plain")
	vSrv := enc(t, srvKey, "orders", "LEGACY", "srv-plain")
	src := dirOf(t, map[string]string{"orders/.env.production": "DB_PASSWORD=" + vApp + "\nLEGACY=" + vSrv + "\nPLAIN=x\n"})

	s := newSecretServer(t, src, nil) // --decrypt off
	code, body, _ := s.get(t, "/orders/production", true)
	snap, err := config.Verify(body, s.pub)
	if code != 200 || err != nil || snap.Values["DB_PASSWORD"] != vApp || snap.Values["LEGACY"] != vSrv {
		t.Fatalf("%d %v %v", code, err, snap)
	}
	if bytes.Contains(body, []byte("app-plain")) || bytes.Contains(body, []byte("srv-plain")) {
		t.Error("plaintext in the snapshot")
	}

	d := newSecretServer(t, src, func(c *config.ServerConfig) { c.DecryptKey = srvKey })
	code, body, _ = d.get(t, "/orders/production", true)
	snap, err = config.Verify(body, d.pub)
	if code != 200 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	if snap.Values["LEGACY"] != "srv-plain" || snap.Sources[0].Values["LEGACY"] != "srv-plain" {
		t.Errorf("the server's value: %v", snap.Values)
	}
	if snap.Values["DB_PASSWORD"] != vApp || snap.Values["PLAIN"] != "x" {
		t.Errorf("the app's value passes through: %v", snap.Values)
	}
	if bytes.Contains(body, []byte("app-plain")) {
		t.Error("the app's secret was decrypted by the server")
	}
	code, body, hdr := d.get(t, "/orders/production.env", true)
	if code != 200 || !strings.Contains(string(body), "LEGACY=\"srv-plain\"") || !config.VerifyEnv(d.pub, body, hdr.Get("X-Config-Signature")) {
		t.Errorf("env: %d %q", code, body)
	}
	for _, l := range []string{d.logs.String(), s.logs.String()} {
		if strings.Contains(l, "plain") {
			t.Errorf("log %q", l)
		}
	}
}

func TestServerDecryptFailsClosed(t *testing.T) {
	srvKey := key(t)
	v := enc(t, srvKey, "orders", "A", "hunter2")
	src := dirOf(t, map[string]string{"orders/.env": "B=" + v + "\n"}) // made for variable A, sits under B
	s := newSecretServer(t, src, func(c *config.ServerConfig) { c.DecryptKey = srvKey })
	code, body, _ := s.get(t, "/orders/-", true)
	if code != 500 || !strings.Contains(string(body), "orders/.env") || !strings.Contains(string(body), "B") ||
		strings.Contains(string(body), v) || strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "signature") {
		t.Errorf("%d %q", code, body)
	}
	if l := s.logs.String(); strings.Contains(l, v) || strings.Contains(l, "hunter2") || !strings.Contains(l, "level=ERROR") {
		t.Errorf("log %q", l)
	}
}

func TestKeysEndpoint(t *testing.T) {
	a, srvKey := key(t), key(t)
	src := dirOf(t, map[string]string{"orders/.env": "A=1\n"})
	s := newSecretServer(t, src, func(c *config.ServerConfig) {
		c.AppKeys = map[string]*config.SecretPublicKey{"orders": a.Public()}
		c.DecryptKey = srvKey
	})
	code, body, hdr := s.get(t, "/_keys/orders", false)
	var kr config.KeyResponse
	if code != 200 || json.Unmarshal(body, &kr) != nil || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %q", code, body)
	}
	if k, err := config.VerifyKey(kr, config.AppSubject("orders"), s.pub); err != nil || k.String() != a.Public().String() {
		t.Errorf("%v", err)
	}
	if bytes.Contains(body, []byte(a.String())) {
		t.Error("the private key is served")
	}
	code, body, _ = s.get(t, "/_keys", false)
	if code != 200 || json.Unmarshal(body, &kr) != nil {
		t.Fatalf("server key: %d", code)
	}
	if k, err := config.VerifyKey(kr, config.ServerSubject, s.pub); err != nil || k.ID() != srvKey.ID() {
		t.Errorf("%v", err)
	}

	// unknown, reserved, malformed and keyless apps are one plain 404
	var first []byte
	for _, p := range []string{"/_keys/nobody", "/_keys/_hooks", "/_keys/_keys", "/_keys/-x", "/_keys/a%2Fb", "/_keys/.git", "/_keys/orders/extra"} {
		code, body, _ := s.get(t, p, false)
		if code != 404 {
			t.Errorf("%s: %d", p, code)
		}
		if first == nil {
			first = body
		} else if !bytes.Equal(first, body) {
			t.Errorf("%s: a different 404: %q vs %q", p, body, first)
		}
	}
	if code, _, _ := s.get(t, "/_keys", false); code != 200 {
		t.Error("server key")
	}
	plain := newSecretServer(t, src, nil)
	if code, _, _ := plain.get(t, "/_keys", false); code != 404 {
		t.Errorf("no decrypt key: %d", code)
	}
	if code, _, _ := plain.get(t, "/_keys/orders", false); code != 404 {
		t.Errorf("no app key: %d", code)
	}
}
