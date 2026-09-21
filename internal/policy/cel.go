package policy

import (
	"encoding/json"
	"fmt"

	"cel.dev/cel-go/cel"

	"github.com/aashish/agentvault/internal/event"
)

// celProgram is one compiled CEL expression, ready for concurrent Eval.
type celProgram struct {
	src string
	prg cel.Program
}

// celEnv builds the shared CEL environment. The event is exposed as
// map(string, dyn) so expressions use event.cmd, event.argv, etc.
func celEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// compileCEL type-checks and compiles src. Errors are returned at load time
// (fail fast) rather than at evaluation time.
func compileCEL(env *cel.Env, ruleName, src string) (*celProgram, error) {
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("rule %q: CEL compile: %w", ruleName, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("rule %q: CEL program: %w", ruleName, err)
	}
	return &celProgram{src: src, prg: prg}, nil
}

// eval runs the program against e and requires a boolean result.
func (c *celProgram) eval(e event.Event) (bool, error) {
	out, _, err := c.prg.Eval(map[string]any{"event": celEventMap(e)})
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression did not return bool (got %v)", out.Type())
	}
	return b, nil
}

// celEventMap flattens an Event into the map exposed to CEL.
// Env and ToolArgs are excluded: secrets never enter policy evaluation;
// tool args are matched structurally via Tool/Path fields instead.
func celEventMap(e event.Event) map[string]any {
	argv := make([]any, len(e.Argv))
	for i, a := range e.Argv {
		argv[i] = a
	}
	return map[string]any{
		"id":      e.ID,
		"source":  string(e.Source),
		"action":  string(e.Action),
		"cmd":     e.Cmd,
		"argv":    argv,
		"raw":     e.Raw,
		"path":    e.Path,
		"host":    e.Host,
		"port":    e.Port,
		"server":  e.Server,
		"tool":    e.Tool,
		"cwd":     e.Cwd,
		"pid":     e.PID,
		"ts_unix": e.Timestamp.Unix(),
	}
}

// toolArgsString is a debugging helper for `policy test` output.
func toolArgsString(e event.Event) string {
	if len(e.ToolArgs) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(e.ToolArgs, &v); err != nil {
		return string(e.ToolArgs)
	}
	b, _ := json.Marshal(v)
	return string(b)
}
