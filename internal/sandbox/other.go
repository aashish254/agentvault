//go:build !darwin

package sandbox

// Available is false off-darwin: Linux Landlock and Windows Job Object
// backends are the v0.3 roadmap. Honest degradation per SPEC §7.
func Available() (bool, string) {
	return false, "kernel sandbox not yet supported on this platform (Seatbelt: macOS; Landlock/JobObjects: roadmap)"
}

// Wrap never runs on unsupported platforms.
func Wrap(argv []string, profile string) []string { return argv }

const PlatformName = "none"
