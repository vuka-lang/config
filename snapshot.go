package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"unicode/utf8"
)

// Snapshot is the configuration one app gets for one profile and label.
type Snapshot struct {
	App     string            `json:"app"`
	Profile string            `json:"profile"`
	Label   string            `json:"label"`
	Version string            `json:"version"`
	Sources []Layer           `json:"sources"`
	Values  map[string]string `json:"values"`
	// Signature is the base64 ed25519 signature of the snapshot's canonical
	// form (see Canonical).
	Signature string `json:"signature,omitempty"`
}

// Layer is one file of a snapshot and the values it gave, before merging.
type Layer struct {
	File    string            `json:"file"`
	Version string            `json:"version"`
	Values  map[string]string `json:"values"`
}

// Tree is the files a Source read at one label.
type Tree struct {
	// Label is the label served: the one asked for, or the default's name.
	Label string
	// Version identifies the tree: a commit hash. Empty means the files are
	// not versioned, and Build hashes their content.
	Version string
	// Files holds the files asked for that exist, by name.
	Files map[string][]byte
}

// Source is where configuration files are kept.
type Source interface {
	// Read returns the named files, those that exist, at label; an empty
	// label is the source's default. An unknown label is ErrNotFound. Names
	// are those ValidFile accepts, slash-separated, relative to the root.
	Read(ctx context.Context, label string, names []string) (Tree, error)
}

// Refresher is a Source that can fetch changes from where it keeps them.
type Refresher interface {
	Refresh(ctx context.Context) error
}

// ErrNotFound is returned by a Source for a label it doesn't have.
var ErrNotFound = errors.New("config: label not found")

// Build merges the files of t for app in profile (see Files) into a
// snapshot. A file that doesn't exist is skipped.
func Build(app, profile string, t Tree) (*Snapshot, error) {
	s := &Snapshot{App: app, Profile: profile, Label: t.Label, Version: t.Version, Sources: []Layer{}, Values: map[string]string{}}
	h := sha256.New()
	for _, name := range Files(app, profile) {
		data, ok := t.Files[name]
		if !ok {
			continue
		}
		if !utf8.Valid(data) {
			return nil, fmt.Errorf("config: %s is not valid UTF-8", name)
		}
		pairs, err := ParseEnv(name, data, nil, s.Values)
		if err != nil {
			return nil, err
		}
		layer := Layer{File: name, Version: t.Version, Values: map[string]string{}}
		sum := sha256.Sum256(data)
		if layer.Version == "" {
			layer.Version = hex.EncodeToString(sum[:])
		}
		fmt.Fprintf(h, "%s\x00%x\x00", name, sum)
		shared := !strings.Contains(name, "/")
		for _, p := range pairs {
			switch {
			case shared && IsCipher(p.Value):
				return nil, fmt.Errorf("%w: %s: %s (every app reads this file, and each app has its own key)", ErrSharedSecret, name, p.Key)
			case !IsCipher(p.Value) && strings.Contains(p.Value, CipherPrefix+cipherVersion+":"):
				return nil, fmt.Errorf("config: %s: %s: a cipher value can't be part of another value", name, p.Key)
			}
			layer.Values[p.Key] = p.Value
		}
		for k, v := range layer.Values {
			s.Values[k] = v
		}
		s.Sources = append(s.Sources, layer)
	}
	if s.Version == "" {
		s.Version = hex.EncodeToString(h.Sum(nil))
	}
	return s, nil
}

// String describes the snapshot with every value masked, so printing one
// never shows a secret.
func (s *Snapshot) String() string {
	keys := make([]string, 0, len(s.Values))
	for k := range s.Values {
		keys = append(keys, k+"=***")
	}
	sort.Strings(keys)
	return fmt.Sprintf("snapshot %s/%s@%.12s [%s]", s.App, s.Profile, s.Version, strings.Join(keys, " "))
}

// LogValue implements slog.LogValuer with the masked description.
func (s *Snapshot) LogValue() slog.Value { return slog.StringValue(s.String()) }

// GoString makes %#v mask values too.
func (s *Snapshot) GoString() string { return s.String() }
