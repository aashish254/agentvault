package policy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// matchPath reports whether path matches any of the glob patterns.
// Patterns support ** (doublestar). A leading ./ pattern is matched
// against the path resolved relative to cwd; a leading ~/ on the event
// path is expanded to the user's home directory.
func matchPath(patterns []string, path, cwd string) bool {
	abs := path
	if strings.HasPrefix(abs, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			abs = filepath.Join(home, abs[2:])
		}
	}
	if cwd != "" && !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	for _, pat := range patterns {
		if ok, err := doublestar.Match(pat, abs); err == nil && ok {
			return true
		}
		if strings.HasPrefix(pat, "./") && cwd != "" {
			joined := filepath.Join(cwd, pat[2:])
			if ok, err := doublestar.Match(joined, abs); err == nil && ok {
				return true
			}
		}
		// Last resort: pattern and path as literally given.
		if ok, err := doublestar.Match(pat, path); err == nil && ok {
			return true
		}
	}
	return false
}

// matchHost reports whether host matches any pattern: exact or *.suffix.
func matchHost(patterns []string, host string) bool {
	host = strings.ToLower(host)
	for _, pat := range patterns {
		pat = strings.ToLower(pat)
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
			continue
		}
		if pat == host {
			return true
		}
	}
	return false
}

// actionIn reports whether a is in the list.
func actionIn(list []string, a string) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// toolIn is actionIn for tool names (kept separate for readability).
func toolIn(list []string, t string) bool { return actionIn(list, t) }

// resolvePath expands a leading ~/, makes an event path absolute
// relative to cwd, and resolves symlinks when the target exists.
// Missing targets are returned as absolute-but-unresolved.
func resolvePath(p, cwd string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	if !filepath.IsAbs(p) && cwd != "" {
		p = filepath.Join(cwd, p)
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}
