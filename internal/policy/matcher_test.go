package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aashish/agentvault/internal/config"
)

// configLoad indirection keeps spec_test.go free of config imports it
// doesn't otherwise need.
func configLoad(p string) (*config.Policy, []byte, error) { return config.Load(p) }

// configLoadYAML parses a policy from a string (for benchmarks and tests).
func configLoadYAML(y string) (*config.Policy, []byte, error) {
	dir, err := os.MkdirTemp("", "av-policy")
	if err != nil {
		return nil, nil, err
	}
	p := filepath.Join(dir, "agentvault.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		return nil, nil, err
	}
	return config.Load(p)
}

func TestHostSuffixMatch(t *testing.T) {
	if !matchHost([]string{"*.example.com"}, "api.example.com") {
		t.Fatal("suffix match failed")
	}
	if matchHost([]string{"*.example.com"}, "example.com") {
		t.Fatal("suffix must not match bare domain")
	}
	if matchHost([]string{"*.example.com"}, "notexample.com") {
		t.Fatal("suffix must not match lookalike")
	}
	if !matchHost([]string{"exact.com"}, "exact.com") {
		t.Fatal("exact match failed")
	}
	if !matchHost([]string{"EXACT.com"}, "exact.com") {
		t.Fatal("host match must be case-insensitive")
	}
}

func TestPathGlobEdgeCases(t *testing.T) {
	if !matchPath([]string{"/work/**"}, "/work/a/b/c.go", "/work") {
		t.Fatal("** should match deep paths")
	}
	if matchPath([]string{"/work/*"}, "/work/a/b.go", "/work") {
		t.Fatal("* must not cross directories")
	}
	if !matchPath([]string{"./**"}, "/work/x.go", "/work") {
		t.Fatal("./** should match absolute paths under cwd")
	}
	if !matchPath([]string{"./**"}, "sub/file.go", "/work") {
		t.Fatal("./** should match relative paths under cwd")
	}
	if matchPath([]string{"/work/**"}, "/other/x.go", "/work") {
		t.Fatal("must not match outside the tree")
	}
}

func TestResolvePatternNeverWidensRelativeGlobs(t *testing.T) {
	// Regression: "./**" must never resolve to "**" (which matches everything).
	if got := resolvePattern("./**"); got != "./**" {
		t.Fatalf("resolvePattern(./**) = %q — must stay literal", got)
	}
	if got := resolvePattern("src/**/*.go"); got != "src/**/*.go" {
		t.Fatalf("relative pattern rewritten: %q", got)
	}
	// Absolute existing prefix gets symlink-resolved but stays equivalent.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	got := resolvePattern(filepath.Join(home, ".ssh", "**"))
	if !strings.HasSuffix(got, filepath.Join(".ssh", "**")) {
		t.Fatalf("suffix lost: %q", got)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("resolved pattern must stay absolute: %q", got)
	}
}

func TestConcurrentEvaluate(t *testing.T) {
	eng := engineFromYAML(t, specPolicy)
	done := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			cmd := []string{"rm", "git", "curl", "ls", "npm", "dd", "cat", "go"}[i]
			for j := 0; j < 500; j++ {
				eng.Evaluate(shellEvent(cmd, "arg"))
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
