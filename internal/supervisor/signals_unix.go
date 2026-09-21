//go:build !windows

package supervisor

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// setProcGroup gives the child its own process group so we can signal
// the whole agent tree without touching the supervisor.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// notifySignals subscribes to the terminating set.
func notifySignals(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

// forwardSignals relays every caught signal to the child's process
// group. SIGKILLing the supervisor orphans the child with the shim
// socket gone — the shims then fail closed, which is the safe end state.
func forwardSignals(ch chan os.Signal, cmd *exec.Cmd) {
	for sig := range ch {
		if cmd.Process == nil {
			return
		}
		// Negative pid = the child's whole process group.
		_ = syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal))
	}
}
