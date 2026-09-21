package policy

import (
	"encoding/json"
	"testing"

	"github.com/aashish/agentvault/internal/event"
)

// FuzzEvaluate: arbitrary JSON → event → engine must never panic, and
// must always return a valid effect (fail closed on garbage).
func FuzzEvaluate(f *testing.F) {
	seeds := []string{
		`{"action":"shell.exec","cmd":"rm","argv":["rm","-rf","/"],"cwd":"/work"}`,
		`{"action":"fs.read","path":"~/.ssh/id_rsa","cwd":"/work"}`,
		`{"action":"net.egress","host":"x","port":-1}`,
		`{}`, `null`, `[]`, `"str"`, `{"argv":[1,2,3]}`, `{"argv":"nope"}`,
		`{"action":"shell.exec","cmd":"git","argv":["git","push"]}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	eng := mustFuzzEngine(f)
	f.Fuzz(func(t *testing.T, s string) {
		var e event.Event
		if err := json.Unmarshal([]byte(s), &e); err != nil {
			return // invalid JSON is the caller's problem, not the engine's
		}
		v := eng.Evaluate(e) // must not panic
		switch v.Effect {
		case event.Allow, event.Deny, event.RequireApproval:
		default:
			t.Fatalf("engine returned invalid effect %q", v.Effect)
		}
	})
}

// FuzzCompileCEL: arbitrary strings must never panic the compiler;
// errors are fine, panics are not.
func FuzzCompileCEL(f *testing.F) {
	for _, s := range []string{
		`event.cmd == "git"`,
		`event.argv.exists(a, a.startsWith("-rf"))`,
		`event.cmd === "git"`, ``, `event.`, `((((`,
		`event.argv[999999999999999999999]`,
	} {
		f.Add(s)
	}
	env, err := celEnv()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, src string) {
		cp, err := compileCEL(env, "fuzz", src)
		if err != nil {
			return
		}
		// A program that compiled must evaluate without panicking.
		_, _ = cp.eval(event.Event{Action: event.ActionShell, Cmd: "x", Argv: []string{"x"}})
	})
}

func mustFuzzEngine(f *testing.F) Engine {
	f.Helper()
	pol, _, err := configLoadYAML(specPolicy)
	if err != nil {
		f.Fatal(err)
	}
	eng, err := NewEngine(pol)
	if err != nil {
		f.Fatal(err)
	}
	return eng
}
