package supervisor

import (
	"fmt"
	"os"
	"strings"

	"github.com/aashish/agentvault/internal/sandbox"
)

// maybeSandbox wraps the child argv in the kernel sandbox when enabled
// and available. The status line is ALWAYS printed — users must know
// exactly how protected they are (honest enforcement, SPEC §1.1).
func (s *Supervisor) maybeSandbox(argv []string, proxyURL string, verbose bool) []string {
	if !s.cfg.Sandbox.Enabled {
		fmt.Fprintln(os.Stderr, "agentvault: kernel sandbox: OFF (not enabled in policy)")
		return argv
	}
	ok, reason := sandbox.Available()
	if !ok {
		fmt.Fprintf(os.Stderr, "agentvault: kernel sandbox: OFF — %s\n", reason)
		return argv
	}

	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	ctx := sandbox.Context{Cwd: cwd, Home: home, HasEgress: proxyURL != ""}
	if s.listener != nil {
		ctx.SockDir = s.listener.socketDir()
	}
	if ctx.HasEgress {
		ctx.ProxyAddr = strings.TrimPrefix(proxyURL, "http://")
	}
	prof := sandbox.Generate(s.cfg, ctx)
	if verbose {
		for _, n := range prof.Notes {
			fmt.Fprintln(os.Stderr, "agentvault: sandbox:", n)
		}
	}
	fmt.Fprintf(os.Stderr, "agentvault: kernel sandbox: ON (%s)\n", sandbox.PlatformName)
	return sandbox.Wrap(argv, prof.SBPL)
}
