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
	"strconv"
	"time"

	"github.com/aashish/agentvault/internal/approval"
	"github.com/aashish/agentvault/internal/audit"
	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/policy"
	"github.com/aashish/agentvault/internal/proxy/egress"
	"github.com/aashish/agentvault/internal/shim"
)

// Supervisor is the runtime root of a wrapped agent session.
type Supervisor struct {
	cfg         *config.Policy
	engine      policy.Engine
	store       *audit.Store
	logger      *audit.Logger
	listener    *listener
	session     string
	approvals   *approval.Daemon // always non-nil: IPC resolution needs it
	egressProxy *egress.Proxy    // nil when egress section disabled
	Verbose     bool             // extra status output (sandbox notes etc.)
}

// New builds the supervisor: compiles the policy, opens the audit store,
// and begins a session attributed to the exact policy bytes.
func New(cfg *config.Policy, policyRaw []byte) (*Supervisor, error) {
	eng, err := policy.NewEngine(withEgressRules(cfg))
	if err != nil {
		return nil, err
	}
	logPath := cfg.Audit.Path
	if logPath == "" {
		return nil, fmt.Errorf("supervisor: audit.path is required")
	}
	store, err := audit.Open(logPath)
	if err != nil {
		return nil, err
	}
	// Retention: archive-then-delete sessions older than the cutoff.
	// Tampered sessions are never deleted; warnings surface on stderr.
	if cfg.Audit.RetentionDays > 0 {
		_, warnings, rerr := store.Retain(cfg.Audit.RetentionDays)
		if rerr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("supervisor: retention: %w", rerr)
		}
		for _, w := range warnings {
			fmt.Fprintln(os.Stderr, "agentvault:", w)
		}
	}
	sessionID := event.NewID()
	if err := store.BeginSession(sessionID, cfg.Agent.Name, cfg.Agent.Command, policyRaw); err != nil {
		_ = store.Close()
		return nil, err
	}
	lg, err := audit.NewLogger(store, logPath+".overflow.jsonl")
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return &Supervisor{
		cfg:       cfg,
		engine:    eng,
		store:     store,
		logger:    lg,
		session:   sessionID,
		approvals: buildApprovalDaemon(cfg),
	}, nil
}

// buildApprovalDaemon assembles channels from config. The daemon always
// exists (IPC resolution via `agentvault approve` needs it); channels
// are notification layers on top.
func buildApprovalDaemon(cfg *config.Policy) *approval.Daemon {
	var channels []approval.Channel
	if cfg.Approvals.Channels.TTY.Enabled {
		if tty := approval.NewTTY(); tty != nil {
			channels = append(channels, tty)
		}
	}
	if cfg.Approvals.Channels.MacOS.Enabled {
		if mc := approval.NewMacOS(); mc != nil {
			channels = append(channels, mc)
		}
	}
	if tg := cfg.Approvals.Channels.Telegram; tg.Enabled {
		token := os.Getenv(tg.BotTokenEnv)
		chatID, err := parseChatID(os.Getenv(tg.ChatIDEnv))
		if err == nil && token != "" {
			channels = append(channels, approval.NewTelegram(token, chatID, ""))
		} else {
			fmt.Fprintln(os.Stderr, "agentvault: telegram misconfigured, channel disabled")
		}
	}
	return approval.New(channels, cfg.Approvals.Timeout)
}

// parseChatID validates Telegram's numeric chat id.
func parseChatID(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

// Approvals exposes the daemon (tests + IPC handlers).
func (s *Supervisor) Approvals() *approval.Daemon { return s.approvals }

// SessionID returns this session's ULID.
func (s *Supervisor) SessionID() string { return s.session }

// ServeOnly starts the IPC listener and egress proxy without a child
// process — the `agentvault daemon` mode for always-on agents. The
// caller blocks on signals; shutdown via Close.
func (s *Supervisor) ServeOnly() error {
	ln, err := startListener(s.session)
	if err != nil {
		return fmt.Errorf("supervisor: ipc listener: %w", err)
	}
	s.listener = ln
	go ln.serve(s)
	if _, err := s.startEgress(); err != nil {
		ln.close()
		return fmt.Errorf("supervisor: egress proxy: %w", err)
	}
	if err := shim.EnsureInstalled(s.cfg.Shims.Binaries); err != nil {
		fmt.Fprintln(os.Stderr, "agentvault: shim install warning:", err)
	}
	return nil
}

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

	// 2. Egress proxy (loopback; enabled when egress.listen is set).
	proxyURL, err := s.startEgress()
	if err != nil {
		return ExitCheckFailed, fmt.Errorf("supervisor: egress proxy: %w", err)
	}
	if s.egressProxy != nil {
		defer s.egressProxy.Close()
	}

	// 3. Install shims (idempotent).
	if err := shim.EnsureInstalled(s.cfg.Shims.Binaries); err != nil {
		fmt.Fprintln(os.Stderr, "agentvault: shim install warning:", err)
	}

	// 4. Kernel sandbox (v0.2): same YAML → Seatbelt profile (macOS).
	argv = s.maybeSandbox(argv, proxyURL, s.Verbose)

	// 5. Spawn child with instrumented environment.
	child, err := spawnChild(argv, childEnv{
		ShimDir:   shim.Dir(),
		SessionID: s.session,
		IPCEnv:    ln.envVars(),
		ProxyURL:  proxyURL,
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

	// 5. Flush audit, seal the session chain, cleanup.
	_ = s.logger.Flush(5 * time.Second)
	return code, nil
}

// Evaluate is the IPC request handler: policy verdict, approval wait
// when required, audit write. May block up to the approval timeout.
func (s *Supervisor) Evaluate(e event.Event) event.Verdict {
	v := s.engine.Evaluate(e)
	if v.Effect != event.RequireApproval {
		s.logger.Log(e, v, nil)
		return v
	}
	dec := s.approvals.Submit(context.Background(), e, v.RuleName)
	final := event.Verdict{
		Effect:     dec.FinalEffect,
		RuleName:   v.RuleName,
		EvalMicros: v.EvalMicros,
	}
	switch {
	case dec.TimedOut:
		final.Message = fmt.Sprintf("approval timed out (rule %q); denied — fail closed", v.RuleName)
	case dec.FinalEffect == event.Allow:
		final.Message = fmt.Sprintf("approved by %s in %s", dec.ApprovedBy, dec.Waited.Round(time.Millisecond))
	default:
		final.Message = fmt.Sprintf("denied by %s", dec.ApprovedBy)
	}
	s.logger.Log(e, v, &dec)
	return final
}

// Close flushes the logger and seals + closes the store.
func (s *Supervisor) Close() error {
	_ = s.logger.Flush(5 * time.Second)
	if err := s.logger.Close(); err != nil {
		return err
	}
	return s.store.Close() // SignAndClose happens inside
}

// Store exposes the audit store (for verify/log within this process).
func (s *Supervisor) Store() *audit.Store { return s.store }

// Exit codes shared with cli (kept here to avoid an import cycle).
const (
	ExitOK          = 0
	ExitUsage       = 2
	ExitCheckFailed = 77
)
