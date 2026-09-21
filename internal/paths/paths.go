// Package paths resolves AgentVault's filesystem locations.
// AGENTVAULT_HOME overrides the base directory (used by tests and by
// users who want an isolated vault).
package paths

import (
	"os"
	"path/filepath"
)

// Home returns the AgentVault base dir: $AGENTVAULT_HOME or ~.
func Home() string {
	if h := os.Getenv("AGENTVAULT_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// VaultDir returns <home>/.agentvault, or $AGENTVAULT_HOME directly when
// the override is set (the override points AT the vault, not its parent).
func VaultDir() string {
	if h := os.Getenv("AGENTVAULT_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".agentvault")
}

// Shims returns the shim directory prepended to supervised PATHs.
func Shims() string { return filepath.Join(VaultDir(), "shims") }

// NOTE: session sockets deliberately do NOT live under the vault dir —
// unix socket paths have a ~104-byte limit, so they live in
// /tmp/av-<uid>/ instead (see internal/supervisor/socket_unix.go).
