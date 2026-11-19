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
	os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
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
	write(t, dir, "orders/.env", "A=1\n")
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
	write(t, dir, "orders/.env", "A=2\n")
	v2 := snapshot(t, s)
	if v2.Values["A"] != "2" || v2.Version == v1.Version {
		t.Errorf("a saved file isn't served: %+v", v2)
	}
	write(t, dir, ".env", "B=1\n")
	v3 := snapshot(t, s)
	if v3.Values["B"] != "1" || v3.Version == v2.Version {
		t.Errorf("a new file isn't served: %+v", v3)
	}
	write(t, dir, "billing/.env", "C=1\n")
	if snapshot(t, s).Version != v3.Version {
		t.Error("another app's file changed this app's version")
	}
	os.Remove(filepath.Join(dir, "orders/.env"))
	if v4 := snapshot(t, s); v4.Values["A"] != "" || v4.Version == v3.Version {
		t.Errorf("a removed file is still served: %+v", v4)
	}
}

func TestOnlyPlainFilesAreRead(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	write(t, outside, "secret.env", "S=leak\n")
	write(t, outside, "orders/.env", "S=leak\n")
	os.MkdirAll(filepath.Join(dir, "orders"), 0o755)
	if err := os.Symlink(filepath.Join(outside, "secret.env"), filepath.Join(dir, "orders", ".env")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.env"), filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	os.Symlink(filepath.Join(outside, "orders"), filepath.Join(dir, "linked"))
	s, _ := New(dir)
	if snap := snapshot(t, s); len(snap.Values) != 0 {
		t.Errorf("followed a symlink: %v", snap.Values)
	}
	tree, err := s.Read(context.Background(), "", config.Files("linked", "production"))
	if err != nil || len(tree.Files) != 0 {
		t.Errorf("followed a symlinked app directory: %v %v", tree.Files, err)
	}
	for _, name := range []string{"../x/.env", "orders/../.env", "a/b/.env", "orders/.envx", ".git/.env", ".git/config", "-x/.env", "orders.env", "/etc/passwd"} {
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

func TestOnlyTheFourPaths(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		".env": "R=1\n", ".env.production": "P=1\n", ".env.local": "LOCAL=1\n", ".env.staging": "STAGING=1\n",
		"orders/.env": "O=1\n", "orders/.env.production": "OP=1\n", "orders/.env.local": "OL=1\n",
		"billing/.env": "B=1\n", ".git/.env": "G=1\n", ".hidden/.env": "H=1\n",
	} {
		write(t, dir, name, body)
	}
	s, _ := New(dir)
	snap := snapshot(t, s)
	if len(snap.Values) != 4 || snap.Values["R"] != "1" || snap.Values["P"] != "1" || snap.Values["O"] != "1" || snap.Values["OP"] != "1" {
		t.Errorf("%v", snap.Values)
	}
}
