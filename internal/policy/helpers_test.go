package policy

import (
	"os"
	"testing"

	"github.com/aashish/agentvault/internal/config"
)

// Thin OS wrappers so tests stay on one mockable seam each.
func mkdirAll(p string) error   { return os.MkdirAll(p, 0o750) }
func symlink(a, b string) error { return os.Symlink(a, b) }
func writeFile(p, s string) error {
	return os.WriteFile(p, []byte(s), 0o600)
}

func defaultPolicyForTest(t *testing.T) *config.Policy {
	t.Helper()
	p := config.DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}
