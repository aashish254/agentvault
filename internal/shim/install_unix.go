//go:build !windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

// candidates: on unix the binary is simply <dir>/<name>.
func candidates(dir, name string) []string {
	return []string{filepath.Join(dir, name)}
}

// EnsureInstalled symlinks ~/.agentvault/shims/<name> → the agentvault
// binary for every requested binary that exists on PATH. Idempotent:
// existing correct symlinks are left alone, wrong ones replaced.
// Binaries not found on PATH are skipped (reported in the warning).
func EnsureInstalled(binaries []string) error {
	dir := Dir()
	if dir == "" {
		return fmt.Errorf("no home directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)

	var skipped []string
	for _, name := range binaries {
		if _, err := realBinary(name); err != nil {
			skipped = append(skipped, name)
			continue
		}
		link := filepath.Join(dir, name)
		if target, err := os.Readlink(link); err == nil && target == self {
			continue // already correct
		}
		_ = os.Remove(link) // stale or wrong
		if err := os.Symlink(self, link); err != nil {
			return fmt.Errorf("symlink %s: %w", name, err)
		}
	}
	if len(skipped) > 0 {
		return fmt.Errorf("not on PATH, skipped: %v", skipped)
	}
	return nil
}
