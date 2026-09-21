package config

import (
	"os"
	"path/filepath"
)

// Discover finds agentvault.yaml the way git finds .git: walk up from the
// working directory until one is found; fall back to the user's home.
// This lets `agentvault run` work from any project folder after a single
// `agentvault init` in the home directory.
func Discover() (string, bool) {
	cwd, err := os.Getwd()
	if err == nil {
		dir := cwd
		for {
			p := filepath.Join(dir, "agentvault.yaml")
			if _, statErr := os.Stat(p); statErr == nil {
				return p, true
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if home, herr := os.UserHomeDir(); herr == nil {
		p := filepath.Join(home, "agentvault.yaml")
		if _, statErr := os.Stat(p); statErr == nil {
			return p, true
		}
	}
	return "", false
}
