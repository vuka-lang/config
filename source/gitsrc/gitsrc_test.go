package gitsrc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vuka-lang/config/v2"
)

type repo struct {
	t   *testing.T
	dir string
}

func (r repo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r repo) commit(msg string, files map[string]string) string {
	r.t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(r.dir, name), []byte(body), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

func newRepo(t *testing.T) repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r := repo{t, t.TempDir()}
	r.git("init", "-q", "-b", "main")
	return r
}

func open(t *testing.T, r repo) *Source {
	t.Helper()
	s, err := Open(context.Background(), Options{URL: r.dir, Dir: filepath.Join(t.TempDir(), "mirror")})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func read(t *testing.T, s *Source, label string) (config.Tree, error) {
	t.Helper()
	return s.Read(context.Background(), label, config.Files("orders", "production"))
}

func value(t *testing.T, s *Source, label, file string) string {
	t.Helper()
	tree, err := read(t, s, label)
	if err != nil {
		t.Fatalf("label %q: %v", label, err)
	}
	return string(tree.Files[file])
}

func TestLabels(t *testing.T) {
	r := newRepo(t)
	c1 := r.commit("one", map[string]string{"orders.env": "A=1\n", "application.env": "S=1\n", "notes.txt": "x"})
	r.git("tag", "v1")
	r.git("branch", "feature/x")
	r.git("checkout", "-q", "feature/x")
	c2 := r.commit("two", map[string]string{"orders.env": "A=feature\n"})
	r.git("checkout", "-q", "main")
	c3 := r.commit("three", map[string]string{"orders.env": "A=3\n"})
	s := open(t, r)

	tree, err := read(t, s, "")
	if err != nil || tree.Label != "main" || tree.Version != c3 || string(tree.Files["orders.env"]) != "A=3\n" {
		t.Errorf("default: %+v %v", tree, err)
	}
	if _, ok := tree.Files["notes.txt"]; ok || string(tree.Files["application.env"]) != "S=1\n" {
		t.Errorf("only the asked files, and those that exist: %v", tree.Files)
	}
	for label, want := range map[string]string{"main": "A=3\n", "v1": "A=1\n", "feature/x": "A=feature\n", c1: "A=1\n", c2[:10]: "A=feature\n"} {
		if got := value(t, s, label, "orders.env"); got != want {
			t.Errorf("label %q: %q, want %q", label, got, want)
		}
	}
	if tree, _ := read(t, s, "v1"); tree.Version != c1 || tree.Label != "v1" {
		t.Errorf("v1: %+v", tree)
	}
	if _, err := read(t, s, "nope"); err != config.ErrNotFound {
		t.Errorf("unknown label: %v", err)
	}
}

func TestHostileLabels(t *testing.T) {
	r := newRepo(t)
	r.commit("one", map[string]string{"orders.env": "A=1\n"})
	s := open(t, r)
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, label := range []string{
		"--upload-pack=touch " + marker, "--output=" + marker, "-h", "../x", "main/../main",
		"main^{tree}", "main:orders.env", "HEAD~0 --", "main\n--help", "@{-1}", "a b", "main..main", "--",
	} {
		if _, err := read(t, s, label); err != config.ErrNotFound {
			t.Errorf("label %q: %v", label, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a label ran a command")
	}
}

func TestRefreshPicksUpCommits(t *testing.T) {
	r := newRepo(t)
	r.commit("one", map[string]string{"orders.env": "A=1\n"})
	s := open(t, r)
	r.commit("two", map[string]string{"orders.env": "A=2\n"})
	if got := value(t, s, "", "orders.env"); got != "A=1\n" {
		t.Fatalf("before a refresh: %q", got)
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := value(t, s, "", "orders.env"); got != "A=2\n" {
		t.Errorf("after Refresh: %q", got)
	}
	r.git("tag", "v2")
	s.Refresh(context.Background())
	if got := value(t, s, "v2", "orders.env"); got != "A=2\n" {
		t.Errorf("a new tag: %q", got)
	}
	r.git("branch", "gone")
	s.Refresh(context.Background())
	if value(t, s, "gone", "orders.env") != "A=2\n" {
		t.Error("a new branch")
	}
	r.git("branch", "-D", "gone")
	s.Refresh(context.Background())
	if _, err := read(t, s, "gone"); err != config.ErrNotFound {
		t.Errorf("a deleted branch: %v", err)
	}
}

func TestPollPicksUpCommits(t *testing.T) {
	r := newRepo(t)
	r.commit("one", map[string]string{"orders.env": "A=1\n"})
	s := open(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Poll(ctx, 20*time.Millisecond); close(done) }()
	r.commit("two", map[string]string{"orders.env": "A=2\n"})
	deadline := time.Now().Add(5 * time.Second)
	for value(t, s, "", "orders.env") != "A=2\n" {
		if time.Now().After(deadline) {
			t.Fatal("the poll never fetched")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestReopenReusesTheMirror(t *testing.T) {
	r := newRepo(t)
	r.commit("one", map[string]string{"orders.env": "A=1\n"})
	mirror := filepath.Join(t.TempDir(), "mirror")
	if _, err := Open(context.Background(), Options{URL: r.dir, Dir: mirror}); err != nil {
		t.Fatal(err)
	}
	r.commit("two", map[string]string{"orders.env": "A=2\n"})
	s, err := Open(context.Background(), Options{URL: r.dir, Dir: mirror})
	if err != nil || value(t, s, "", "orders.env") != "A=2\n" {
		t.Errorf("reopen: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(context.Background(), Options{}); err == nil {
		t.Error("no options")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	if _, err := Open(context.Background(), Options{URL: filepath.Join(t.TempDir(), "none"), Dir: filepath.Join(t.TempDir(), "m")}); err == nil {
		t.Error("clone of nothing")
	}
	if _, err := Open(context.Background(), Options{URL: "--upload-pack=x", Dir: filepath.Join(t.TempDir(), "m")}); err == nil {
		t.Error("a URL that is an option")
	}
}
