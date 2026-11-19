package dirsrc

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vuka-lang/config/v2"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, s *Source) *config.Snapshot {
	t.Helper()
	tree, err := s.Read(context.Background(), "", config.Files("orders", "production"))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := config.Build("orders", "production", tree)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestChangesAreServedAndVersioned(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "orders.env", "A=1\n")
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	v1 := snapshot(t, s)
	if v1.Values["A"] != "1" || v1.Version == "" {
		t.Fatalf("%+v", v1)
	}
	if snapshot(t, s).Version != v1.Version {
		t.Error("version changed without a change")
	}
	write(t, dir, "orders.env", "A=2\n")
	v2 := snapshot(t, s)
	if v2.Values["A"] != "2" || v2.Version == v1.Version {
		t.Errorf("a saved file isn't served: %+v", v2)
	}
	write(t, dir, "application.env", "B=1\n")
	v3 := snapshot(t, s)
	if v3.Values["B"] != "1" || v3.Version == v2.Version {
		t.Errorf("a new file isn't served: %+v", v3)
	}
	write(t, dir, "billing.env", "C=1\n")
	if snapshot(t, s).Version != v3.Version {
		t.Error("another app's file changed this app's version")
	}
	os.Remove(filepath.Join(dir, "orders.env"))
	if v4 := snapshot(t, s); v4.Values["A"] != "" || v4.Version == v3.Version {
		t.Errorf("a removed file is still served: %+v", v4)
	}
}

func TestOnlyPlainFilesAreRead(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	write(t, outside, "secret.env", "S=leak\n")
	if err := os.Symlink(filepath.Join(outside, "secret.env"), filepath.Join(dir, "orders.env")); err != nil {
		t.Fatal(err)
	}
	s, _ := New(dir)
	if snap := snapshot(t, s); len(snap.Values) != 0 {
		t.Errorf("followed a symlink: %v", snap.Values)
	}
	for _, name := range []string{"../x.env", "a/b.env", "orders.txt"} {
		if _, err := s.Read(context.Background(), "", []string{name}); err == nil {
			t.Errorf("read %q", name)
		}
	}
	if _, err := s.Read(context.Background(), "main", nil); err != config.ErrNotFound {
		t.Errorf("a directory has one label: %v", err)
	}
	if _, err := New(filepath.Join(dir, "nope")); err == nil {
		t.Error("missing dir")
	}
}
