// Package dirsrc serves configuration files from a local directory.
package dirsrc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vuka-lang/config/v2"
)

// Source reads the directory on every call, so a saved file is served at
// once. A directory has one label, the empty one. Symbolic links are not
// followed.
type Source struct{ dir string }

// New returns a Source over dir.
func New(dir string) (*Source, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("config: %s is not a directory", dir)
	}
	return &Source{dir}, nil
}

// Read implements config.Source.
func (s *Source) Read(_ context.Context, label string, names []string) (config.Tree, error) {
	if label != "" {
		return config.Tree{}, config.ErrNotFound
	}
	t := config.Tree{Files: map[string][]byte{}}
	for _, name := range names {
		if !config.ValidFile(name) {
			return t, fmt.Errorf("config: bad file name %q", name)
		}
		path := filepath.Join(s.dir, filepath.FromSlash(name))
		if dir := filepath.Dir(path); dir != s.dir {
			if st, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) || err == nil && !st.IsDir() {
				continue
			} else if err != nil {
				return t, err
			}
		}
		st, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) || err == nil && !st.Mode().IsRegular() {
			continue
		}
		if err != nil {
			return t, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return t, err
		}
		t.Files[name] = data
	}
	return t, nil
}
