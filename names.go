package config

import (
	"regexp"
	"strings"
)

var (
	appName     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)
	profileName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	labelName   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)
)

// NoProfile is how a request names the absence of a profile (VUKA_ENV
// unset). It is not a valid profile, so it can't be mistaken for one.
const NoProfile = "-"

// ValidApp reports whether s can name an app: one directory name of
// letters, digits, hyphens and underscores, not starting with a hyphen or
// a dot. "_hooks" and "_keys" are the server's own paths.
func ValidApp(s string) bool {
	return len(s) <= 64 && appName.MatchString(s) && s != "_hooks" && s != "_keys"
}

// ValidProfile reports whether s can name a profile; the empty profile is
// the absence of one and is valid too.
func ValidProfile(s string) bool {
	if s == "" {
		return true
	}
	return len(s) <= 64 && profileName.MatchString(s) && !strings.Contains(s, "..") &&
		!strings.HasSuffix(s, ".") && !strings.HasSuffix(s, ".env")
}

// ValidFile reports whether name is a path Files can return: ".env",
// ".env.<profile>", or either inside one app's directory.
func ValidFile(name string) bool {
	dir, base, nested := strings.Cut(name, "/")
	if !nested {
		dir, base = "", dir
	} else if !ValidApp(dir) {
		return false
	}
	if base == ".env" {
		return true
	}
	p, ok := strings.CutPrefix(base, ".env.")
	return ok && p != "" && ValidProfile(p)
}

// ValidLabel reports whether s can name a label: a branch, tag or commit.
// It never starts with a hyphen and holds none of the characters git reads
// as revision syntax, so it is safe as a git argument.
func ValidLabel(s string) bool {
	switch {
	case len(s) > 200, !labelName.MatchString(s):
		return false
	case strings.Contains(s, ".."), strings.Contains(s, "//"), strings.HasSuffix(s, "/"), strings.HasSuffix(s, "."):
		return false
	case strings.HasSuffix(s, ".lock"), strings.HasSuffix(s, ".env"), s == "watch":
		return false
	}
	return true
}

// Files lists the paths that make up the snapshot of app in profile, in
// merge order: the later wins. They are the shared files at the root and
// the app's own, in its directory; with no profile, only the two ".env".
func Files(app, profile string) []string {
	files := []string{".env"}
	if profile != "" {
		files = append(files, ".env."+profile)
	}
	files = append(files, app+"/.env")
	if profile != "" {
		files = append(files, app+"/.env."+profile)
	}
	return files
}
