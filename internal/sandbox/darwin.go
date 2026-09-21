//go:build darwin

package sandbox

import "os/exec"

// Available reports whether sandbox-exec exists on this system.
// Deprecated by Apple since Catalina but present and functional through
// current macOS — we degrade loudly, never silently.
func Available() (bool, string) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		return false, "sandbox-exec not found on PATH"
	}
	return true, ""
}

// Wrap rewrites argv to run under the generated Seatbelt profile:
//
//	sandbox-exec -p '<profile>' <argv...>
func Wrap(argv []string, profile string) []string {
	return append([]string{"sandbox-exec", "-p", profile, "--"}, argv...)
}

// PlatformName for status output.
const PlatformName = "macOS Seatbelt (sandbox-exec)"
