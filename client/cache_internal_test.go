package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vuka-lang/config/v2"
)

func TestCacheKeepsCiphertextAndDecryptsOnLoad(t *testing.T) {
	k, err := config.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := config.Encrypt(k.Public(), "orders", "DB_PASSWORD", []byte("plain-pw-1234"))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap := &config.Snapshot{App: "orders", Profile: "production", Version: "v", Sources: []config.Layer{}, Values: map[string]string{"DB_PASSWORD": ct}}
	snap.Sign(priv)
	raw, _ := json.Marshal(snap)

	c := Config{App: "orders", Profile: "production", Token: "tok", Key: base64Std(pub), SecretKeys: k.String(), Cache: filepath.Join(t.TempDir(), "c")}
	if err := writeCache(c, raw); err != nil {
		t.Fatal(err)
	}
	file, _ := os.ReadFile(c.Cache)
	if bytes.Contains(file, []byte("plain-pw-1234")) {
		t.Error("plaintext in the cache file")
	}
	cached, err := readCache(c)
	if err != nil {
		t.Fatal(err)
	}
	if cached.Values["DB_PASSWORD"] != ct {
		t.Errorf("the cache holds %q, want the ciphertext", cached.Values["DB_PASSWORD"])
	}
	values, err := (&Client{c: c}).resolve(cached)
	if err != nil || values["DB_PASSWORD"] != "plain-pw-1234" {
		t.Errorf("%v %v", values, err)
	}
	c.SecretKeys = ""
	if _, err := (&Client{c: c}).resolve(cached); err == nil || !strings.Contains(err.Error(), "DB_PASSWORD") || strings.Contains(err.Error(), ct) {
		t.Errorf("%v", err)
	}
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
