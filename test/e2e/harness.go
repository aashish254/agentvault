//go:build !windows

// Package e2e runs the real agentvault binary against scripted fake
// agents. Everything is hermetic: AGENTVAULT_HOME points at a temp dir,
// so shims, sockets, and audit logs never touch the real home.
package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Harness holds an isolated AgentVault installation.
type Harness struct {
	T        *testing.T
	Bin      string // built agentvault binary
	VaultDir string // AGENTVAULT_HOME
	WorkDir  string // sandbox the fake agent "works" in
	Policy   string // path to agentvault.yaml
}

// New builds the binary and lays out the isolated vault.
func New(t *testing.T, policyYAML string) *Harness {
	t.Helper()

	vault := t.TempDir()
	work := t.TempDir()
	bin := filepath.Join(t.TempDir(), "agentvault")

	build := exec.Command("go", "build", "-o", bin, "github.com/aashish/agentvault/cmd/agentvault")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agentvault: %v\n%s", err, out)
	}

	policyPath := filepath.Join(vault, "agentvault.yaml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Harness{T: t, Bin: bin, VaultDir: vault, WorkDir: work, Policy: policyPath}
}

// Run executes `agentvault run -- <argv...>` with the isolated env and
// returns combined output and the process exit code.
func (h *Harness) Run(argv ...string) (output string, exitCode int) {
	return h.RunEnv(nil, argv...)
}

// RunEnv is Run with extra environment variables for the child.
func (h *Harness) RunEnv(extra map[string]string, argv ...string) (output string, exitCode int) {
	h.T.Helper()
	args := append([]string{"-c", h.Policy, "run", "--"}, argv...)
	cmd := exec.Command(h.Bin, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	cmd.Dir = h.WorkDir // never run fake agents in the real repo
	cmd.Env = append(os.Environ(),
		"AGENTVAULT_HOME="+h.VaultDir,
		"AV_WORK="+h.WorkDir,
		"AV_BIN="+h.Bin,
		"AV_FIXTURES="+filepath.Join(repoRoot(h.T), "test", "fixtures"),
	)
	for k, v := range extra {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	err := cmd.Run()
	output = buf.String()
	if err == nil {
		return output, 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return output, ee.ExitCode()
	}
	h.T.Fatalf("run failed to execute: %v\n%s", err, output)
	return "", -1
}

// AsyncRun is a running `agentvault run` process.
type AsyncRun struct {
	cmd *exec.Cmd
	buf *bytes.Buffer
}

// Start begins `agentvault run -- <argv...>` without blocking.
func (h *Harness) Start(argv ...string) *AsyncRun {
	h.T.Helper()
	args := append([]string{"-c", h.Policy, "run", "--"}, argv...)
	cmd := exec.Command(h.Bin, args...)
	buf := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = buf, buf
	cmd.Dir = h.WorkDir
	cmd.Env = append(os.Environ(),
		"AGENTVAULT_HOME="+h.VaultDir,
		"AV_WORK="+h.WorkDir,
		"AV_BIN="+h.Bin,
		"AV_FIXTURES="+filepath.Join(repoRoot(h.T), "test", "fixtures"),
	)
	if err := cmd.Start(); err != nil {
		h.T.Fatalf("start run: %v", err)
	}
	return &AsyncRun{cmd: cmd, buf: buf}
}

// Wait blocks for the run to finish and returns output + exit code.
func (r *AsyncRun) Wait(t *testing.T) (string, int) {
	t.Helper()
	err := r.cmd.Wait()
	if err == nil {
		return r.buf.String(), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return r.buf.String(), ee.ExitCode()
	}
	t.Fatalf("run wait: %v", err)
	return "", -1
}

// Approve runs `agentvault approve <list|allow|deny> [id]` against the
// live session and returns combined output.
func (h *Harness) Approve(args ...string) (string, error) {
	h.T.Helper()
	cmd := exec.Command(h.Bin, append([]string{"-c", h.Policy, "approve"}, args...)...)
	cmd.Env = append(os.Environ(), "AGENTVAULT_HOME="+h.VaultDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// AuditLog returns the audit records via `agentvault log --export json`
// (exercising the CLI like a user would, not poking the DB directly).
func (h *Harness) AuditLog() string {
	h.T.Helper()
	cmd := exec.Command(h.Bin, "-c", h.Policy, "log", "--export", "json")
	cmd.Env = append(os.Environ(), "AGENTVAULT_HOME="+h.VaultDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.T.Fatalf("log --export: %v\n%s", err, out)
	}
	return string(out)
}

// Verify runs `agentvault verify` and returns (exitCode, output).
func (h *Harness) Verify() (int, string) {
	h.T.Helper()
	cmd := exec.Command(h.Bin, "-c", h.Policy, "verify")
	cmd.Env = append(os.Environ(), "AGENTVAULT_HOME="+h.VaultDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	}
	h.T.Fatalf("verify failed to execute: %v\n%s", err, out)
	return -1, ""
}

// repoRoot walks up from the test file to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	// test/e2e → module root is two levels up.
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
