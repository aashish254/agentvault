//go:build !windows

package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicyFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o750); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(repoRoot(t), "test", "fixtures", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return p
}
