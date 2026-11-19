package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalForm(t *testing.T) {
	raw := `{
	  "values": {"b": "<&>\u2028é", "a": "x\ny\"z"},
	  "version": "v1", "signature": "ignored",
	  "sources": [{"version": "v1", "file": "a.env", "values": {"z": "1", "a": "2"}}],
	  "app": "orders", "profile": "production", "label": "main"
	}`
	want := "vuka-config snapshot v1\n" +
		`{"app":"orders","label":"main","profile":"production","sources":[{"file":"a.env","values":{"a":"2","z":"1"},"version":"v1"}],` +
		`"values":{"a":"x\ny\"z","b":"<&>\u2028é"},"version":"v1"}`
	got, err := Canonical([]byte(raw))
	if err != nil || string(got) != want {
		t.Errorf("%q\nwant %q (%v)", got, want, err)
	}
	// Whitespace, member order and the signature member don't matter.
	again, _ := Canonical([]byte(`{"label":"main","app":"orders","version":"v1","profile":"production","values":{"a":"x\ny\"z","b":"<&>\u2028é"},"sources":[{"values":{"z":"1","a":"2"},"file":"a.env","version":"v1"}]}`))
	if !bytes.Equal(got, again) {
		t.Error("not canonical")
	}
}

func testSnapshot(t *testing.T, priv ed25519.PrivateKey) *Snapshot {
	t.Helper()
	s, err := Build("orders", "production", Tree{Label: "main", Version: "abc", Files: files("orders.env", "X=1\nY=<&>\n")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerify(t *testing.T) {
	pub, priv := testKeys(t)
	s := testSnapshot(t, priv)
	raw, _ := json.Marshal(s)
	got, err := Verify(raw, pub)
	if err != nil || got.Values["Y"] != "<&>" || got.Version != "abc" {
		t.Fatalf("%+v %v", got, err)
	}
	pretty, _ := json.MarshalIndent(s, "", "    ")
	if _, err := Verify(pretty, pub); err != nil {
		t.Errorf("reformatted: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(raw, other); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong key: %v", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	pub, priv := testKeys(t)
	raw, _ := json.Marshal(testSnapshot(t, priv))
	for name, tamper := range map[string]func(string) string{
		"value":     func(s string) string { return strings.Replace(s, `"X":"1"`, `"X":"2"`, 1) },
		"app":       func(s string) string { return strings.Replace(s, `"app":"orders"`, `"app":"billing"`, 1) },
		"version":   func(s string) string { return strings.Replace(s, `"abc"`, `"abd"`, 1) },
		"extra key": func(s string) string { return strings.Replace(s, `"values":{`, `"values":{"EVIL":"1",`, 1) },
		"extra member": func(s string) string {
			return strings.Replace(s, `{"app"`, `{"hook":"x","app"`, 1)
		},
		"no signature": func(s string) string { return regexpSig(s) },
	} {
		bad := tamper(string(raw))
		if bad == string(raw) {
			t.Fatalf("%s: no change", name)
		}
		if _, err := Verify([]byte(bad), pub); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := Verify([]byte(`{"signature": 5}`), pub); err == nil {
		t.Error("garbage")
	}
}

func regexpSig(s string) string {
	i := strings.Index(s, `,"signature":"`)
	return s[:i] + "}"
}

func TestEnvSignature(t *testing.T) {
	pub, priv := testKeys(t)
	body := FormatEnv(map[string]string{"A": "1"})
	sig := SignEnv(priv, body)
	if !VerifyEnv(pub, body, sig) || VerifyEnv(pub, append(body, 'x'), sig) {
		t.Error("env body signature")
	}
	// A snapshot signature is not an env signature.
	s := testSnapshot(t, priv)
	if VerifyEnv(pub, body, s.Signature) {
		t.Error("domains are not separated")
	}
}

func TestKeyParsing(t *testing.T) {
	pub, priv := testKeys(t)
	if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Error(err)
	}
	k, err := ParsePrivateKey(base64.StdEncoding.EncodeToString(priv.Seed()))
	if err != nil || !k.Equal(priv) {
		t.Errorf("%v", err)
	}
	if _, err := ParsePublicKey("nope"); err == nil {
		t.Error("bad public key")
	}
	if _, err := ParsePrivateKey("nope"); err == nil {
		t.Error("bad seed")
	}
}
