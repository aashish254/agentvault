//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// candidates: on Windows an executable may be .exe/.cmd/.bat; PATHEXT
// ordering is approximated with the common cases.
func candidates(dir, name string) []string {
	if filepath.Ext(name) != "" {
		return []string{filepath.Join(dir, name)}
	}
	return []string{
		filepath.Join(dir, name+".exe"),
		filepath.Join(dir, name+".cmd"),
		filepath.Join(dir, name+".bat"),
	}
}

// EnsureInstalled writes ~/.agentvault/shims/<name>.cmd wrappers:
//
//	@echo off
//	"<self>" __shim <name> %*
//
// Windows symlink creation needs privileges, so wrappers are the
// portable mechanism. Idempotent: identical wrappers are left alone.
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

	var skipped []string
	for _, name := range binaries {
		if _, err := realBinary(name); err != nil {
			skipped = append(skipped, name)
			continue
		}
		wrapper := filepath.Join(dir, name+".cmd")
		content := "@echo off\r\n\"" + self + "\" __shim " + name + " %*\r\nexit /b %ERRORLEVEL%\r\n"
		if existing, err := os.ReadFile(wrapper); err == nil && string(existing) == content {
			continue
		}
		if err := os.WriteFile(wrapper, []byte(content), 0o700); err != nil {
			return fmt.Errorf("write %s wrapper: %w", name, err)
		}
	}
	if len(skipped) > 0 {
		return fmt.Errorf("not on PATH, skipped: %v", skipped)
	}
	return nil
}

var _ = strings.Contains
