package config

import (
	"slices"
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	for _, app := range []string{"orders", "billing_2", "A1"} {
		if !ValidApp(app) {
			t.Errorf("app %q rejected", app)
		}
	}
	for _, app := range []string{"", "application", "order-service", "_hooks", "a/b", "..", "a.b", "-x", strings.Repeat("a", 65)} {
		if ValidApp(app) {
			t.Errorf("app %q accepted", app)
		}
	}
	for _, p := range []string{"production", "us-east", "v1.2", "default"} {
		if !ValidProfile(p) {
			t.Errorf("profile %q rejected", p)
		}
	}
	for _, p := range []string{"", "-x", "a/b", "a..b", ".x", "x.", "a b"} {
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
	want := []string{"application.env", "application-production.env", "orders.env", "orders-production.env"}
	if got := Files("orders", "production"); !slices.Equal(got, want) {
		t.Errorf("%v", got)
	}
}
