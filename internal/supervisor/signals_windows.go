//go:build windows

package supervisor

import (
	"os"
	"os/exec"
	"os/signal"
)

// setProcGroup: Windows has no POSIX process groups; child processes
// are terminated individually via Process.Signal/Kill.
func setProcGroup(cmd *exec.Cmd) {}

// notifySignals: only os.Interrupt (Ctrl+C) is deliverable on Windows.
func notifySignals(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

// forwardSignals relays Interrupt to the child process.
func forwardSignals(ch chan os.Signal, cmd *exec.Cmd) {
	for sig := range ch {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(sig)
	}
}
