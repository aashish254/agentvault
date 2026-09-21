package policy

import (
	"testing"
)

// BenchmarkEvaluate is the CI performance gate: policy eval must stay
// comfortably under 1ms p99 (SPEC §4.3). Typical local result is ~1-5µs.
func BenchmarkEvaluate(b *testing.B) {
	eng := mustBenchEngine(b)
	ev := shellEvent("git", "push", "origin", "main")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(ev)
	}
}

func mustBenchEngine(b *testing.B) Engine {
	b.Helper()
	// specPolicy is defined in spec_test.go and mirrors agentvault.example.yaml.
	pol, raw, err := configLoadYAML(specPolicy)
	_ = raw
	if err != nil {
		b.Fatal(err)
	}
	eng, err := NewEngine(pol)
	if err != nil {
		b.Fatal(err)
	}
	return eng
}
