// Package shim implements the PATH-interception channel (SPEC §1.2 #2).
// Shims for dangerous binaries live in ~/.agentvault/shims, which the
// supervisor prepends to the child's PATH. Each shim re-invokes this
// binary as `agentvault __shim <name> [args...]`, which asks the
// supervisor for a verdict, then execs the real binary or exits 126.
package shim

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/paths"
)

// Exit codes (contract from SPEC §4.1).
const (
	ExitDenied      = 126
	ExitCheckFailed = 77
)

// Dir is the shim directory (prepended to the child's PATH).
func Dir() string { return paths.Shims() }

// Handle runs the __shim flow: build the event, ask the supervisor,
// then exec the real binary or refuse. Returns the process exit code.
func Handle(name string, args []string) int {
	verdict, err := askSupervisor(buildEvent(name, args))
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentvault: policy check failed (%v) — refusing to run %s (fail closed)\n",
			err, name)
		return ExitCheckFailed
	}
	switch verdict.Effect {
	case event.Allow:
		return execReal(name, args) // platform-specific; only returns on error
	default:
		fmt.Fprintf(os.Stderr, "agentvault: denied")
		if verdict.RuleName != "" {
			fmt.Fprintf(os.Stderr, " by rule %q", verdict.RuleName)
		}
		if verdict.Message != "" {
			fmt.Fprintf(os.Stderr, ": %s", verdict.Message)
		}
		fmt.Fprintln(os.Stderr)
		return ExitDenied
	}
}

// buildEvent constructs the shell.exec event for this invocation.
func buildEvent(name string, args []string) event.Event {
	cwd, _ := os.Getwd()
	argv := append([]string{name}, args...)
	return event.Event{
		ID:        event.NewID(),
		SessionID: os.Getenv("AGENTVAULT_SESSION"),
		Timestamp: time.Now().UTC(),
		Source:    event.SourceShim,
		Action:    event.ActionShell,
		Cmd:       name,
		Argv:      argv,
		Raw:       strings.Join(argv, " "),
		Cwd:       cwd,
		PID:       os.Getpid(),
	}
}

// askSupervisor sends the event over the platform IPC channel.
// Dial timeout is short: a dead supervisor must not hang the agent.
func askSupervisor(e event.Event) (event.EvalResponse, error) {
	conn, err := dialIPC(200 * time.Millisecond)
	if err != nil {
		return event.EvalResponse{}, err
	}
	defer func() { _ = conn.Close() }()
	req := event.EvalRequest{Type: "eval", Token: os.Getenv("AGENTVAULT_TOKEN"), Event: e}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return event.EvalResponse{}, err
	}
	var resp event.EvalResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return event.EvalResponse{}, err
	}
	if resp.Type != "verdict" {
		return event.EvalResponse{}, fmt.Errorf("unexpected response type %q", resp.Type)
	}
	return resp, nil
}

// realBinary locates the true binary by scanning PATH *after* the shim
// directory, and never resolves to our own executable.
func realBinary(name string) (string, error) {
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	shimDir := Dir()
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if samePath(dir, shimDir) {
			continue // skip ourselves
		}
		for _, cand := range candidates(dir, name) {
			info, err := os.Stat(cand)
			if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
				continue
			}
			resolved, _ := filepath.EvalSymlinks(cand)
			if self != "" && resolved == self {
				continue // a stray symlink back to agentvault
			}
			return cand, nil
		}
	}
	return "", fmt.Errorf("real binary %q not found on PATH (after shims)", name)
}

// samePath compares two directories, resolving symlinks.
func samePath(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	if errA == nil {
		a = ra
	}
	if errB == nil {
		b = rb
	}
	return a == b
}
