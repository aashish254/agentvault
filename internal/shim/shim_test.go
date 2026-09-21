//go:build !windows

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeBin writes an executable stub into dir.
func makeBin(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRealBinarySkipsShimDir(t *testing.T) {
	vault := t.TempDir()
	t.Setenv("AGENTVAULT_HOME", vault)
	shimDir := Dir()
	if err := os.MkdirAll(shimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realDir := t.TempDir()
	want := makeBin(t, realDir, "mycmd")
	// A shim symlink with the same name sits in the shim dir.
	self, _ := os.Executable()
	if err := os.Symlink(self, filepath.Join(shimDir, "mycmd")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)

	got, err := realBinary("mycmd")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("realBinary = %q, want %q (shim dir must be skipped)", got, want)
	}
}

func TestRealBinaryNotFound(t *testing.T) {
	t.Setenv("AGENTVAULT_HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir()) // empty dir only
	if _, err := realBinary("definitely-not-real-xyz"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestEnsureInstalledIdempotent(t *testing.T) {
	vault := t.TempDir()
	t.Setenv("AGENTVAULT_HOME", vault)
	binDir := t.TempDir()
	makeBin(t, binDir, "fakerm")
	t.Setenv("PATH", binDir)

	if err := EnsureInstalled([]string{"fakerm"}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(Dir(), "fakerm")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	if target != self {
		t.Fatalf("shim points at %q, want %q", target, self)
	}
	// Second run must be a no-op and report nothing missing.
	if err := EnsureInstalled([]string{"fakerm"}); err != nil {
		t.Fatalf("idempotent run: %v", err)
	}
}

func TestEnsureInstalledSkipsMissing(t *testing.T) {
	t.Setenv("AGENTVAULT_HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	err := EnsureInstalled([]string{"not-a-real-binary-xyz"})
	if err == nil || !strings.Contains(err.Error(), "skipped") {
		t.Fatalf("want skip warning, got %v", err)
	}
}

func TestBuildEvent(t *testing.T) {
	t.Setenv("AGENTVAULT_SESSION", "sess-x")
	e := buildEvent("rm", []string{"-rf", "/tmp/x"})
	if e.Action != "shell.exec" || e.Source != "shim" || e.Cmd != "rm" {
		t.Fatalf("bad event: %+v", e)
	}
	if e.Argv[0] != "rm" || e.Argv[2] != "/tmp/x" || e.Raw != "rm -rf /tmp/x" {
		t.Fatalf("bad argv/raw: %+v", e)
	}
	if e.SessionID != "sess-x" || e.Cwd == "" || e.PID == 0 || e.ID == "" {
		t.Fatalf("missing metadata: %+v", e)
	}
}

func TestHandleWithoutSupervisorFailsClosed(t *testing.T) {
	// No AGENTVAULT_SOCK and no listener: Handle must exit 77, never exec.
	t.Setenv("AGENTVAULT_SOCK", filepath.Join(t.TempDir(), "nope.sock"))
	t.Setenv("AGENTVAULT_SESSION", "x")
	if code := Handle("rm", []string{"-rf", "/"}); code != ExitCheckFailed {
		t.Fatalf("want %d, got %d", ExitCheckFailed, code)
	}
}
