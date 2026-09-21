package policy

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
)

// corpus mirrors testdata/corpus.yaml. Anyone can add a test case by
// editing YAML — no Go required.
type corpus struct {
	Policy string       `yaml:"policy"`
	Cases  []corpusCase `yaml:"cases"`
}

type corpusCase struct {
	Name  string       `yaml:"name"`
	Event event.Event  `yaml:"event"`
	Want  event.Effect `yaml:"want"`
	Rule  string       `yaml:"rule"`
}

// TestCorpus runs every case in testdata/corpus.yaml against the policy
// file it names (the repo's agentvault.example.yaml). This is the contract
// between the README's promises and the engine's behavior.
func TestCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "corpus.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("corpus.yaml: %v", err)
	}
	if len(c.Cases) < 30 {
		t.Fatalf("corpus must contain ≥30 cases (SPEC §5 week 1), got %d", len(c.Cases))
	}
	pol, _, err := config.Load(filepath.Join("testdata", c.Policy))
	if err != nil {
		t.Fatalf("corpus policy: %v", err)
	}
	eng, err := NewEngine(pol)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tc := range c.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			if seen[tc.Name] {
				t.Fatalf("duplicate case name %q", tc.Name)
			}
			seen[tc.Name] = true
			switch tc.Want {
			case event.Allow, event.Deny, event.RequireApproval:
			default:
				t.Fatalf("bad want %q (allow|deny|require_approval)", tc.Want)
			}
			v := eng.Evaluate(tc.Event)
			if v.Effect != tc.Want || v.RuleName != tc.Rule {
				t.Fatalf("got %s/%s, want %s/%s", v.Effect, v.RuleName, tc.Want, tc.Rule)
			}
		})
	}
}
