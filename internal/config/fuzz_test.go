package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad: arbitrary bytes must never panic the loader. Errors are
// expected; panics are bugs.
func FuzzLoad(f *testing.F) {
	seeds := []string{
		"version: 1\ndefaults: {action: deny}\nrules: []\n",
		"version: 1\ndefaults: {action: allow}\nrules: []\n",
		"", ":", "[]", "null", "{{{{",
		"version: 1\ndefaults:\n  approval_timeout: notaduration\n",
		"version: 1\nrules:\n  - name: x\n    match: {cel: 'event.'}\n    effect: deny\ndefaults: {action: deny}\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		p := filepath.Join(t.TempDir(), "fuzz.yaml")
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		pol, _, err := Load(p)
		if err != nil {
			return
		}
		// A policy that loaded must remain internally consistent.
		if err := pol.Validate(); err != nil {
			t.Fatalf("Load returned policy that fails Validate: %v", err)
		}
	})
}
