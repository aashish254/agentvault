//go:build !windows

package shim

import (
	"fmt"
	"os"
	"syscall"
)

// execReal replaces this process with the real binary — zero wrapper
// overhead after the verdict (SPEC §4.2). Only returns on error.
func execReal(name string, args []string) int {
	bin, err := realBinary(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentvault:", err)
		return ExitCheckFailed
	}
	argv := append([]string{bin}, args...)
	// #nosec G204 -- exec of the policy-approved real binary is the feature.
	if err := syscall.Exec(bin, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "agentvault: exec %s: %v\n", bin, err)
		return ExitCheckFailed
	}
	return 0 // unreachable
}
