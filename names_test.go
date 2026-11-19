package config

import (
	"slices"
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	for _, app := range []string{"orders", "billing_2", "A1", "order-service", "_x", "a-b-c"} {
		if !ValidApp(app) {
			t.Errorf("app %q rejected", app)
		}
	}
	for _, app := range []string{"", "-x", ".git", "..", ".", ".hidden", "a/b", "a\\b", "a.b", "_hooks", "_keys", "a b", "a\x00", "orders/..", strings.Repeat("a", 65)} {
		if ValidApp(app) {
			t.Errorf("app %q accepted", app)
		}
	}
	for _, p := range []string{"", "production", "us-east", "v1.2", "dev_1"} {
		if !ValidProfile(p) {
			t.Errorf("profile %q rejected", p)
		}
	}
	for _, p := range []string{"-", "-x", ".x", "a/b", "a..b", "x.", "a b", "x.env", "../x"} {
		if ValidProfile(p) {
			t.Errorf("profile %q accepted", p)
		}
	}
	for _, l := range []string{"main", "v42", "feature/x", "3f2a1c9", "release-1.2"} {
		if !ValidLabel(l) {
			t.Errorf("label %q rejected", l)
		}
	}
	for _, l := range []string{"", "--upload-pack=touch /tmp/x", "-main", "../x", "a/../b", "a//b", "main/", "x.lock", "x.env", "watch", "a b", "a:b", "a~1", "a^", "a@{1}", "a?", "a*", "a[b", `a\b`, "x\n", "main^{tree}"} {
		if ValidLabel(l) {
			t.Errorf("label %q accepted", l)
		}
	}
}

func TestFiles(t *testing.T) {
	for _, c := range []struct {
		app, profile string
		want         []string
	}{
		{"orders", "production", []string{".env", ".env.production", "orders/.env", "orders/.env.production"}},
		{"order-service", "", []string{".env", "order-service/.env"}},
	} {
		if got := Files(c.app, c.profile); !slices.Equal(got, c.want) {
			t.Errorf("%v", got)
		}
		for _, f := range Files(c.app, c.profile) {
			if !ValidFile(f) {
				t.Errorf("Files returned %q, which ValidFile rejects", f)
			}
		}
	}
}

// With hyphens in app names, the paths of two apps never meet.
func TestFilesDoNotCollide(t *testing.T) {
	a := Files("a", "b-c")
	b := Files("a-b", "c")
	for _, x := range a {
		if slices.Contains(b, x) && x != ".env" {
			t.Errorf("%q is read by both", x)
		}
	}
	if !slices.Contains(a, "a/.env.b-c") || !slices.Contains(b, "a-b/.env.c") {
		t.Errorf("%v %v", a, b)
	}
}

func TestValidFile(t *testing.T) {
	for _, f := range []string{".env", ".env.production", "orders/.env", "order-service/.env.us-east"} {
		if !ValidFile(f) {
			t.Errorf("%q rejected", f)
		}
	}
	for _, f := range []string{"", "env", ".env.", ".env.local.env", "../.env", "orders/../.env", ".git/.env", ".git/config", "a/b/.env", "orders/.envx", "orders/other", "/etc/passwd", "orders/", ".env/x", "-x/.env", ".envrc"} {
		if ValidFile(f) {
			t.Errorf("%q accepted", f)
		}
	}
}
