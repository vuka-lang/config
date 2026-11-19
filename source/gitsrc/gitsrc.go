// Package gitsrc serves configuration files from a git repository, kept as
// a local mirror by the git binary.
package gitsrc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vuka-lang/config/v2"
)

// Options configures Open.
type Options struct {
	// URL is the repository to clone; Dir is where the mirror lives.
	URL, Dir string
	// SSHKey is the path of a private key for an ssh URL.
	SSHKey string
	// Token authenticates https URLs, sent as the password of basic auth.
	Token string
	Log   *slog.Logger
}

// Source serves the files of any branch, tag or commit of the repository.
// A snapshot's version is the commit hash.
type Source struct {
	o     Options
	env   []string
	fetch sync.Mutex

	mu    sync.Mutex
	cache map[string][]byte // commit and name, to the file (nil: absent)
}

// Open clones the repository into o.Dir, or fetches into the mirror already
// there.
func Open(ctx context.Context, o Options) (*Source, error) {
	if o.URL == "" || o.Dir == "" {
		return nil, errors.New("gitsrc: URL and Dir are required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	s := &Source{o: o, cache: map[string][]byte{}}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !strings.HasPrefix(k, "GIT_") || k == "GIT_SSH" || k == "GIT_ASKPASS" || k == "GIT_SSH_COMMAND" {
			s.env = append(s.env, kv)
		}
	}
	s.env = append(s.env, "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=file:git:http:https:ssh")
	if o.SSHKey != "" {
		s.env = append(s.env, "GIT_SSH_COMMAND=ssh -i "+shellQuote(o.SSHKey)+" -o IdentitiesOnly=yes -o BatchMode=yes")
	}
	if o.Token != "" {
		auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + o.Token))
		s.env = append(s.env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "+auth)
	}
	if _, err := os.Stat(o.Dir + "/HEAD"); err == nil {
		return s, s.Refresh(ctx)
	}
	if _, err := s.git(ctx, "", "clone", "--mirror", "--", o.URL, o.Dir); err != nil {
		return nil, err
	}
	return s, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Refresh fetches the repository's changes.
func (s *Source) Refresh(ctx context.Context) error {
	s.fetch.Lock()
	defer s.fetch.Unlock()
	_, err := s.git(ctx, s.o.Dir, "fetch", "--prune", "--quiet", "origin")
	return err
}

// Poll refreshes every interval until ctx ends.
func (s *Source) Poll(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
				s.o.Log.Error("gitsrc: fetching", "err", err)
			}
		}
	}
}

// Read implements config.Source. The label is checked before it goes near
// a git command line.
func (s *Source) Read(ctx context.Context, label string, names []string) (config.Tree, error) {
	t := config.Tree{Label: label, Files: map[string][]byte{}}
	if label == "" {
		out, err := s.git(ctx, s.o.Dir, "symbolic-ref", "--short", "HEAD")
		if err != nil {
			return t, err
		}
		label = strings.TrimSpace(out)
		t.Label = label
	}
	if !config.ValidLabel(label) {
		return t, config.ErrNotFound
	}
	out, err := s.git(ctx, s.o.Dir, "rev-parse", "--verify", "--quiet", "--end-of-options", label+"^{commit}")
	commit := strings.TrimSpace(out)
	if err != nil || len(commit) < 40 {
		return t, config.ErrNotFound
	}
	t.Version = commit
	var missing []string
	s.mu.Lock()
	for _, name := range names {
		if data, ok := s.cache[commit+"/"+name]; ok {
			if data != nil {
				t.Files[name] = data
			}
		} else {
			missing = append(missing, name)
		}
	}
	s.mu.Unlock()
	if len(missing) == 0 {
		return t, nil
	}
	args := append([]string{"ls-tree", "-z", commit, "--"}, missing...)
	listing, err := s.git(ctx, s.o.Dir, args...)
	if err != nil {
		return t, err
	}
	found := map[string][]byte{}
	for _, ent := range strings.Split(listing, "\x00") {
		meta, name, ok := strings.Cut(ent, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 || f[1] != "blob" || f[0] == "120000" {
			continue
		}
		data, err := s.git(ctx, s.o.Dir, "cat-file", "blob", f[2])
		if err != nil {
			return t, err
		}
		found[name] = []byte(data)
	}
	s.mu.Lock()
	if len(s.cache) > 1024 {
		clear(s.cache)
	}
	for _, name := range missing {
		s.cache[commit+"/"+name] = found[name]
		if d, ok := found[name]; ok {
			t.Files[name] = d
		}
	}
	s.mu.Unlock()
	return t, nil
}

func (s *Source) git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = s.env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("gitsrc: git %s: %w: %s", args[0], err, strings.TrimSpace(redact(errb.String(), s.o)))
	}
	return out.String(), nil
}

func redact(s string, o Options) string {
	if o.Token != "" {
		s = strings.ReplaceAll(s, o.Token, "***")
	}
	return s
}
