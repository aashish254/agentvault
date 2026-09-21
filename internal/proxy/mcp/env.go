package mcp

import "os"

// Thin wrappers so tests can stub the environment.

var (
	sessionFromEnv = func() string { return os.Getenv("AGENTVAULT_SESSION") }
	cwdOf          = func() string { d, _ := os.Getwd(); return d }
	pidOf          = os.Getpid
)
