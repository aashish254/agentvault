// Package supervisor orchestrates `agentvault run`: it owns the policy
// engine, the audit logger, the shim→supervisor IPC listener, and the
// child agent process. Any startup failure aborts before the child
// spawns (fail closed).
package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/aashish/agentvault/internal/audit"
	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/policy"
	"github.com/aashish/agentvault/internal/shim"
)

// Supervisor is the runtime root of a wrapped agent session.
type Supervisor struct {
	cfg      *config.Policy
	engine   policy.Engine
	logger   audit.Logger
	listener *listener
	session  string

	// approvals are wired in Week 4; until then require_approval
	// degrades to deny with an explanatory message (fail closed).
	approvalAvailable bool
}

// New builds the supervisor: compiles the policy, opens the audit log.
func New(cfg *config.Policy) (*Supervisor, error) {
	eng, err := policy.NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	logPath := cfg.Audit.Path
	if logPath == "" {
		return nil, fmt.Errorf("supervisor: audit.path is required")
	}
	lg, err := audit.OpenJSONL(logPath)
	if err != nil {
		return nil, err
	}
	return &Supervisor{
		cfg:     cfg,
		engine:  eng,
		logger:  lg,
		session: event.NewID(),
	}, nil
}

// SessionID returns this session's ULID.
func (s *Supervisor) SessionID() string { return s.session }

// Run executes argv as a supervised child and returns its exit code.
// It blocks until the child exits or a terminating signal arrives.
func (s *Supervisor) Run(ctx context.Context, argv []string) (int, error) {
	if len(argv) == 0 {
		return ExitUsage, fmt.Errorf("supervisor: no command given after --")
	}

	// 1. IPC listener (unix socket / loopback TCP, platform-specific).
	ln, err := startListener(s.session)
	if err != nil {
		return ExitCheckFailed, fmt.Errorf("supervisor: ipc listener: %w", err)
	}
	s.listener = ln
	defer ln.close()
	go ln.serve(s)

	// 2. Install shims (idempotent).
	if err := shim.EnsureInstalled(s.cfg.Shims.Binaries); err != nil {
		fmt.Fprintln(os.Stderr, "agentvault: shim install warning:", err)
	}

	// 3. Spawn child with instrumented environment.
	child, err := spawnChild(argv, childEnv{
		ShimDir:   shim.Dir(),
		SessionID: s.session,
		IPCEnv:    ln.envVars(),
	})
	if err != nil {
		return ExitCheckFailed, fmt.Errorf("supervisor: spawn %q: %w", argv[0], err)
	}

	// 4. Forward terminating signals to the child.
	sigCh := make(chan os.Signal, 4)
	notifySignals(sigCh)
	defer signal.Stop(sigCh)
	go forwardSignals(sigCh, child)

	code := waitChild(child)

	// 5. Flush audit, cleanup.
	_ = s.logger.Flush(0)
	return code, nil
}

// Evaluate is the IPC request handler: policy verdict + audit write.
func (s *Supervisor) Evaluate(e event.Event) event.Verdict {
	v := s.engine.Evaluate(e)
	if v.Effect == event.RequireApproval && !s.approvalAvailable {
		// Week 2 degradation: no approval daemon yet, so asks become
		// denies with an explanation. Fail closed (SPEC §1.1).
		v = event.Verdict{
			Effect:   event.Deny,
			RuleName: v.RuleName,
			Message:  fmt.Sprintf("requires approval, but the approval daemon is not running (rule %q); denied by fail-closed default", v.RuleName),
		}
	}
	s.logger.Log(e, v, nil)
	return v
}

// Close releases resources.
func (s *Supervisor) Close() error { return s.logger.Close() }

// Exit codes shared with cli (kept here to avoid an import cycle).
const (
	ExitOK          = 0
	ExitUsage       = 2
	ExitCheckFailed = 77
)
