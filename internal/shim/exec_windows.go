//go:build windows

package shim

import (
	"fmt"
	"os"
	"os/exec"
)

// execReal: Windows has no execve; spawn the real binary with stdio
// passthrough and propagate its exit code. Adds one process of overhead
// per shimmed command — acceptable on Windows, documented in SPEC §7.
func execReal(name string, args []string) int {
	bin, err := realBinary(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentvault:", err)
		return ExitCheckFailed
	}
	// #nosec G204 -- exec of the policy-approved real binary is the feature.
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "agentvault: exec %s: %v\n", bin, err)
		return ExitCheckFailed
	}
	return 0
}
