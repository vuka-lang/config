package config

import (
	"regexp"
	"strings"
)

var (
	appName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_]*$`)
	profileName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	labelName   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)
)

// ValidApp reports whether s can name an app. Hyphens are left out so that
// the file orders-production.env is only ever app orders in profile
// production; "application" is the shared files' name.
func ValidApp(s string) bool { return len(s) <= 64 && appName.MatchString(s) && s != "application" }

// ValidProfile reports whether s can name a profile.
func ValidProfile(s string) bool {
	return len(s) <= 64 && profileName.MatchString(s) && !strings.Contains(s, "..") && !strings.HasSuffix(s, ".")
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

// Files lists the files that make up the snapshot of app in profile, in
// merge order: the later wins.
func Files(app, profile string) []string {
	return []string{
		"application.env",
		"application-" + profile + ".env",
		app + ".env",
		app + "-" + profile + ".env",
	}
}
