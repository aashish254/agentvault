package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/policy"
)

func TestInitNonInteractive(t *testing.T) {
	t.Setenv("AGENTVAULT_HOME", t.TempDir())
	dest := filepath.Join(t.TempDir(), "agentvault.yaml")

	stdout, _, err := runCLI(t, "-c", dest, "init", "--non-interactive")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "wrote "+dest) {
		t.Fatalf("missing confirmation: %q", stdout)
	}

	// The written file must load AND compile into an engine.
	pol, _, err := config.Load(dest)
	if err != nil {
		t.Fatalf("init wrote a policy that fails to load: %v", err)
	}
	if _, err := policy.NewEngine(pol); err != nil {
		t.Fatalf("init wrote a policy that fails to compile: %v", err)
	}
	if pol.Defaults.Action != config.EffectDeny {
		t.Fatal("default policy must fail closed")
	}
	// TTY approvals on, Telegram off by default.
	if !pol.Approvals.Channels.TTY.Enabled || pol.Approvals.Channels.Telegram.Enabled {
		t.Fatal("wrong channel defaults")
	}
	// Shims got installed into the isolated vault.
	if _, err := os.Stat(filepath.Join(os.Getenv("AGENTVAULT_HOME"), "shims")); err != nil {
		t.Fatal("shim dir not created")
	}
}

func TestInitRefusesOverwrite(t *testing.T) {
	t.Setenv("AGENTVAULT_HOME", t.TempDir())
	dir := t.TempDir()
	dest := filepath.Join(dir, "agentvault.yaml")
	if err := os.WriteFile(dest, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Existing file at the default name triggers the guard only when the
	// path is the default; for explicit paths we currently overwrite.
	// Pin the behavior we want for the default case:
	cwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "init", "--non-interactive"); err == nil {
		t.Fatal("must refuse to overwrite an existing default policy")
	}
}

func TestInitInteractiveSkipsTelegram(t *testing.T) {
	t.Setenv("AGENTVAULT_HOME", t.TempDir())
	dest := filepath.Join(t.TempDir(), "p.yaml")
	// Scripted answers: "n" to Telegram setup.
	stdout, _, err := runCLIWithInput(t, "n\n", "-c", dest, "init")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "skipped") {
		t.Fatalf("telegram skip path not exercised: %q", stdout)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal("policy not written")
	}
}

// runCLIWithInput drives a command with scripted stdin.
func runCLIWithInput(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	var outBuf, errBuf strings.Builder
	root := newRootCmd()
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetIn(strings.NewReader(input))
	root.SetArgs(args)
	err := root.Execute()
	return outBuf.String(), errBuf.String(), err
}
