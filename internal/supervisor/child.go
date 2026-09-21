package supervisor

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// childEnv carries the instrumentation injected into the agent process.
type childEnv struct {
	ShimDir   string
	SessionID string
	IPCEnv    []string // platform-specific: AGENTVAULT_SOCK or ADDR+TOKEN
	ProxyURL  string   // loopback egress proxy ("" = disabled)
}

// spawnChild starts argv with stdio wired to the terminal and the
// AgentVault environment prepended. The child runs in its own process
// group so signal forwarding never kills the supervisor itself.
func spawnChild(argv []string, env childEnv) (*exec.Cmd, error) {
	// #nosec G204 -- the user-supplied child command is the product's input.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = buildChildEnv(env)
	setProcGroup(cmd) // platform-specific
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	return cmd, nil
}

// buildChildEnv: PATH gets the shim dir first; AGENTVAULT_* identifies
// the session and IPC channel; AGENTVAULT_HOME passes through when set
// (test isolation / custom vault location). Everything else passes.
func buildChildEnv(env childEnv) []string {
	out := []string{
		"PATH=" + env.ShimDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"AGENTVAULT_SESSION=" + env.SessionID,
	}
	if h := os.Getenv("AGENTVAULT_HOME"); h != "" {
		out = append(out, "AGENTVAULT_HOME="+h)
	}
	if env.ProxyURL != "" {
		out = append(out,
			"HTTP_PROXY="+env.ProxyURL, "HTTPS_PROXY="+env.ProxyURL,
			"http_proxy="+env.ProxyURL, "https_proxy="+env.ProxyURL,
			// Loopback targets must never round-trip through the proxy.
			"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1",
		)
	}
	out = append(out, env.IPCEnv...)
	for _, kv := range os.Environ() {
		k := strings.SplitN(kv, "=", 2)[0]
		kl := strings.ToLower(k)
		if strings.EqualFold(k, "PATH") || strings.HasPrefix(k, "AGENTVAULT_") {
			continue // ours wins
		}
		if env.ProxyURL != "" && (kl == "http_proxy" || kl == "https_proxy" || kl == "no_proxy") {
			continue // replaced by ours
		}
		out = append(out, kv)
	}
	return out
}

// waitChild blocks until exit and returns the child's exit code.
func waitChild(cmd *exec.Cmd) int {
	err := cmd.Wait()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return ExitCheckFailed
}
