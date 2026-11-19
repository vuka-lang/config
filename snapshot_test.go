package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func files(kv ...string) map[string][]byte {
	m := map[string][]byte{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = []byte(kv[i+1])
	}
	return m
}

func TestBuildPrecedence(t *testing.T) {
	tree := Tree{Files: files(
		"application.env", "A=app\nB=app\nC=app\nD=app\nSHARED=1\n",
		"application-production.env", "B=app-prod\nC=app-prod\nD=app-prod\n",
		"orders.env", "C=orders\nD=orders\nONLY=orders\n",
		"orders-production.env", "D=orders-prod\n",
		"billing.env", "SHARED=billing\nBILLING=1\n",
		"application-staging.env", "B=staging\n",
		"orders-staging.env", "D=staging\n",
	)}
	s, err := Build("orders", "production", tree)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "app", "B": "app-prod", "C": "orders", "D": "orders-prod", "SHARED": "1", "ONLY": "orders"}
	if len(s.Values) != len(want) {
		t.Errorf("%v", s.Values)
	}
	for k, v := range want {
		if s.Values[k] != v {
			t.Errorf("%s = %q, want %q", k, s.Values[k], v)
		}
	}
	var names []string
	for _, l := range s.Sources {
		names = append(names, l.File)
	}
	if strings.Join(names, " ") != "application.env application-production.env orders.env orders-production.env" {
		t.Errorf("sources %v", names)
	}
	if s.Sources[3].Values["D"] != "orders-prod" || len(s.Sources[3].Values) != 1 {
		t.Errorf("a source holds its own values: %v", s.Sources[3].Values)
	}

	st, _ := Build("orders", "staging", tree)
	if st.Values["B"] != "staging" || st.Values["D"] != "staging" || st.Values["C"] != "orders" {
		t.Errorf("staging: %v", st.Values)
	}
}

func TestBuildMissingFiles(t *testing.T) {
	s, err := Build("orders", "production", Tree{Files: files("orders-production.env", "X=1\n")})
	if err != nil || len(s.Sources) != 1 || s.Values["X"] != "1" {
		t.Errorf("%+v %v", s, err)
	}
	s, err = Build("orders", "production", Tree{})
	if err != nil || len(s.Values) != 0 || s.Sources == nil {
		t.Errorf("%+v %v", s, err)
	}
	raw, _ := json.Marshal(s)
	if !strings.Contains(string(raw), `"sources":[]`) || !strings.Contains(string(raw), `"values":{}`) {
		t.Errorf("empty snapshot encodes as %s", raw)
	}
}

func TestBuildExpandsAcrossFilesNotTheEnvironment(t *testing.T) {
	t.Setenv("SERVER_ONLY_SECRET", "leak")
	s, err := Build("orders", "p", Tree{Files: files(
		"application.env", "HOST=db.internal\n",
		"orders.env", "URL=postgres://${HOST}/x\nLEAK=[$SERVER_ONLY_SECRET]\n",
	)})
	if err != nil || s.Values["URL"] != "postgres://db.internal/x" || s.Values["LEAK"] != "[]" {
		t.Errorf("%v %v", s.Values, err)
	}
}

func TestBuildVersions(t *testing.T) {
	a, _ := Build("orders", "p", Tree{Files: files("orders.env", "X=1\n", "billing.env", "Y=1\n")})
	b, _ := Build("orders", "p", Tree{Files: files("orders.env", "X=1\n", "billing.env", "Y=2\n")})
	c, _ := Build("orders", "p", Tree{Files: files("orders.env", "X=2\n")})
	if a.Version == "" || a.Version != b.Version {
		t.Error("a file of another app changed the version")
	}
	if a.Version == c.Version {
		t.Error("content changed, version didn't")
	}
	if a.Sources[0].Version == c.Sources[0].Version {
		t.Error("file versions are content hashes")
	}
	g, _ := Build("orders", "p", Tree{Version: "3f2a1c", Files: files("orders.env", "X=1\n")})
	if g.Version != "3f2a1c" || g.Sources[0].Version != "3f2a1c" {
		t.Errorf("a tree's version is the snapshot's and its files': %+v", g)
	}
}

func TestBuildRejectsBadFiles(t *testing.T) {
	if _, err := Build("orders", "p", Tree{Files: files("orders.env", "A=1\nnope\n")}); err == nil || strings.Contains(err.Error(), "A=1") {
		t.Errorf("syntax: %v", err)
	}
	if _, err := Build("orders", "p", Tree{Files: files("orders.env", "A=\xff\n")}); err == nil {
		t.Error("invalid UTF-8")
	}
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}
