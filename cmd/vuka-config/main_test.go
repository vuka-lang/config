package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/config/v2/source/dirsrc"
)

func lines(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		i := strings.LastIndex(l, " ")
		m[strings.TrimSpace(l[:i])] = l[i+1:]
	}
	return m
}

func TestKeygenApp(t *testing.T) {
	var out bytes.Buffer
	if err := keygenApp([]string{"orders"}, &out); err != nil {
		t.Fatal(err)
	}
	var priv, line string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		switch {
		case strings.Contains(l, "VUKA_CONFIG_SECRET_KEY"):
			priv = l[strings.LastIndex(l, " ")+1:]
		case strings.Contains(l, "--app-keys"):
			line = l[strings.LastIndex(l, " ")+1:]
		}
	}
	k, err := config.ParseSecretKey(priv)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	m, err := config.ParseAppKeys(line)
	if err != nil || m["orders"].ID() != k.ID() {
		t.Fatalf("%v %v", m, err)
	}

	file := filepath.Join(t.TempDir(), "orders.key")
	out.Reset()
	if err := keygenApp([]string{"--out", file, "orders"}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 || len(strings.TrimSpace(string(b))) == 0 || strings.Contains(out.String(), strings.TrimSpace(string(b))) {
		t.Errorf("the key file: %v, printed %q", st.Mode(), out.String())
	}
	if err := keygenApp([]string{"--out", file, "orders"}, &out); err == nil {
		t.Error("overwrote a key file")
	}
	for _, bad := range [][]string{nil, {"a", "b"}, {"_keys"}, {"--server", "orders"}} {
		if err := keygenApp(bad, io.Discard); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	out.Reset()
	if err := keygenApp([]string{"--server"}, &out); err != nil || !strings.Contains(out.String(), "VUKA_CONFIG_DECRYPT_KEY") {
		t.Errorf("%v %q", err, out.String())
	}
}

func TestEncryptReadsStdinNotArgv(t *testing.T) {
	k, _ := config.GenerateSecretKey()
	pub := k.Public().String()
	base := []string{"--app", "orders", "--var", "DB_PASSWORD", "--pub", pub}

	var out bytes.Buffer
	if err := encrypt(base, strings.NewReader("hunter2\n"), &out); err != nil {
		t.Fatal(err)
	}
	got, err := config.Decrypt([]*config.SecretKey{k}, "orders", "DB_PASSWORD", strings.TrimSpace(out.String()))
	if err != nil || got != "hunter2" {
		t.Errorf("%q %v", got, err)
	}
	if strings.Contains(out.String(), "hunter2") {
		t.Error("the value is printed")
	}

	out.Reset()
	if err := encrypt(append(base, "hunter2"), strings.NewReader("x"), &out); err == nil || out.Len() != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("a value in argv: %v %q", err, out.String())
	}
	out.Reset()
	if err := encrypt(base, strings.NewReader("a\r\nb\n\n"), &out); err != nil {
		t.Fatal(err)
	}
	if got, _ := config.Decrypt([]*config.SecretKey{k}, "orders", "DB_PASSWORD", strings.TrimSpace(out.String())); got != "a\r\nb\n" {
		t.Errorf("only the final newline is dropped: %q", got)
	}
	for name, args := range map[string][]string{
		"no var":      {"--app", "orders", "--pub", pub},
		"bad var":     {"--app", "orders", "--var", "A B", "--pub", pub},
		"no app":      {"--var", "X", "--pub", pub},
		"no key":      {"--app", "orders", "--var", "X"},
		"both keys":   {"--app", "orders", "--var", "X", "--pub", pub, "--server", "http://x"},
		"bad pub":     {"--app", "orders", "--var", "X", "--pub", "zz"},
		"server, key": {"--app", "orders", "--var", "X", "--server", "http://127.0.0.1:1"},
	} {
		if err := encrypt(args, strings.NewReader("v"), io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := encrypt(base, strings.NewReader("\n"), io.Discard); err == nil {
		t.Error("an empty value")
	}
}

func keyServer(t *testing.T, tamper func(*config.KeyResponse)) (url string, signing string, app, srv *config.SecretKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	app, _ = config.GenerateSecretKey()
	srv, _ = config.GenerateSecretKey()
	dir := t.TempDir()
	src, _ := dirsrc.New(dir)
	h, err := config.Server(config.ServerConfig{Source: src, Key: priv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tokens:  map[string]string{"orders": config.HashToken("t")},
		AppKeys: map[string]*config.SecretPublicKey{"orders": app.Public()}, DecryptKey: srv})
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler = h
	if tamper != nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			var kr config.KeyResponse
			if json.Unmarshal(rec.Body.Bytes(), &kr) != nil {
				w.WriteHeader(rec.Code)
				return
			}
			tamper(&kr)
			json.NewEncoder(w).Encode(kr)
		})
	}
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return s.URL, base64.StdEncoding.EncodeToString(pub), app, srv
}

func TestEncryptFetchesTheVerifiedKey(t *testing.T) {
	url, signing, app, srv := keyServer(t, nil)

	var out bytes.Buffer
	if err := encrypt([]string{"--app", "orders", "--var", "X", "--server", url, "--key", signing}, strings.NewReader("v1\n"), &out); err != nil {
		t.Fatal(err)
	}
	if got, err := config.Decrypt([]*config.SecretKey{app}, "orders", "X", strings.TrimSpace(out.String())); err != nil || got != "v1" {
		t.Errorf("%q %v", got, err)
	}

	out.Reset()
	if err := encrypt([]string{"--app", "orders", "--var", "X", "--server-key", "--server", url, "--key", signing}, strings.NewReader("v2\n"), &out); err != nil {
		t.Fatal(err)
	}
	if got, err := config.Decrypt([]*config.SecretKey{srv}, "orders", "X", strings.TrimSpace(out.String())); err != nil || got != "v2" {
		t.Errorf("server key: %q %v", got, err)
	}

	other, _, _ := ed25519.GenerateKey(rand.Reader)
	out.Reset()
	if err := encrypt([]string{"--app", "orders", "--var", "X", "--server", url, "--key", base64.StdEncoding.EncodeToString(other)}, strings.NewReader("v"), &out); err == nil || out.Len() != 0 {
		t.Errorf("verified with another signing key: %v", err)
	}
	if err := encrypt([]string{"--app", "nobody", "--var", "X", "--server", url, "--key", signing}, strings.NewReader("v"), io.Discard); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("unknown app: %v", err)
	}
	t.Setenv("VUKA_CONFIG_KEY", signing)
	if err := encrypt([]string{"--app", "orders", "--var", "X", "--server", url}, strings.NewReader("v"), io.Discard); err != nil {
		t.Errorf("the key from the environment: %v", err)
	}
}

func TestEncryptRejectsTamperedKeyResponses(t *testing.T) {
	evil, _ := config.GenerateSecretKey()
	for name, tamper := range map[string]func(*config.KeyResponse){
		"substituted key": func(r *config.KeyResponse) { r.Key, r.ID = evil.Public().String(), evil.ID() },
		"another subject": func(r *config.KeyResponse) { r.Subject = "app billing" },
		"no signature":    func(r *config.KeyResponse) { r.Signature = "" },
	} {
		url, signing, _, _ := keyServer(t, tamper)
		var out bytes.Buffer
		err := encrypt([]string{"--app", "orders", "--var", "X", "--server", url, "--key", signing}, strings.NewReader("v"), &out)
		if err == nil || out.Len() != 0 {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestLoadSettings(t *testing.T) {
	k, _ := config.GenerateSecretKey()
	t.Setenv("VUKA_CONFIG_APP_KEYS", "orders="+k.Public().String())
	m, err := loadAppKeys("")
	if err != nil || len(m) != 1 {
		t.Fatalf("%v %v", m, err)
	}
	file := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(file, []byte("# keys\nbilling="+k.Public().String()+"\n"), 0o600)
	if m, err := loadAppKeys(file); err != nil || m["billing"] == nil || m["orders"] != nil {
		t.Errorf("%v %v", m, err)
	}
	t.Setenv("VUKA_CONFIG_DECRYPT_KEY", "")
	if _, err := loadDecryptKey(""); err == nil {
		t.Error("--decrypt without a key")
	}
	t.Setenv("VUKA_CONFIG_DECRYPT_KEY", k.String())
	if got, err := loadDecryptKey(""); err != nil || got.ID() != k.ID() {
		t.Errorf("%v", err)
	}
}
