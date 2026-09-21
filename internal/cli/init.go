package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/aashish/agentvault/internal/approval"
	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/paths"
	"github.com/aashish/agentvault/internal/shim"
)

// knownAgents are auto-detected on PATH for the wizard's suggestions.
var knownAgents = []struct{ name, bin string }{
	{"opencode", "opencode"},
	{"claude-code", "claude"},
	{"openclaw", "openclaw"},
	{"aider", "aider"},
	{"cursor-agent", "cursor-agent"},
}

func newInitCmd() *cobra.Command {
	var nonInteractive bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up AgentVault: policy file, shims, optional Telegram approvals",
		RunE: func(cmd *cobra.Command, args []string) error {
			in := bufio.NewReader(cmd.InOrStdin())
			out := cmd.OutOrStdout()
			return runInit(in, out, nonInteractive)
		},
	}
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "write a sane default policy without prompting")
	return cmd
}

func runInit(in *bufio.Reader, out interface{ Write([]byte) (int, error) }, nonInteractive bool) error {
	p := func(format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }
	p("🛡  AgentVault init")
	p("")

	// 1. Policy file.
	pol := config.DefaultPolicy()
	pol.Agent.Name = "my-agent"

	if !nonInteractive {
		// Agent detection.
		var found []string
		for _, a := range knownAgents {
			if _, err := exec.LookPath(a.bin); err == nil {
				found = append(found, a.bin)
				pol.Agent.Name = a.name
			}
		}
		if len(found) > 0 {
			p("detected agents on PATH: %s", strings.Join(found, ", "))
			p("  → agent.name set to %q (edit anytime)", pol.Agent.Name)
		} else {
			p("no known agents found on PATH (opencode/claude/openclaw/...) — using generic defaults")
		}

		// Telegram setup (optional).
		p("")
		p("Telegram approvals let you approve/deny from your phone.")
		if askYN(in, out, "Set up Telegram approvals now?", false) {
			p("  1. Open Telegram, message @BotFather, send /newbot")
			p("  2. Copy the bot token it gives you")
			token := ask(in, out, "  Paste bot token (or empty to skip):")
			if token != "" {
				p("  3. Message your new bot once, then find your chat id:")
				p("     https://api.telegram.org/bot<TOKEN>/getUpdates")
				chatStr := ask(in, out, "  Paste your chat id (number):")
				if chatID, err := strconv.ParseInt(strings.TrimSpace(chatStr), 10, 64); err == nil && chatID != 0 {
					if verifyTelegram(out, token, chatID) {
						// Env var NAMES, not secrets — gosec false positive.
						// #nosec G101
						pol.Approvals.Channels.Telegram = config.TelegramCfg{
							Enabled:     true,
							BotTokenEnv: "AGENTVAULT_TELEGRAM_TOKEN",
							ChatIDEnv:   "AGENTVAULT_TELEGRAM_CHAT_ID",
						}
						p("  ✓ test message delivered — Telegram channel enabled")
						p("")
						p("  Add to your shell profile (~/.zshrc):")
						p("    export AGENTVAULT_TELEGRAM_TOKEN=%q", token)
						p("    export AGENTVAULT_TELEGRAM_CHAT_ID=%q", chatStr)
						p("  (the policy references env var NAMES, never the secrets)")
					}
				} else {
					p("  ! invalid chat id — skipping Telegram (re-run init anytime)")
				}
			}
		} else {
			p("  skipped — TTY prompts remain enabled; Telegram stays off")
		}
	}

	// 2. Write the policy.
	dest := flagConfig
	if dest == "agentvault.yaml" {
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("%s already exists — edit it or use --config to write elsewhere", dest)
		}
	}
	data, err := yaml.Marshal(pol)
	if err != nil {
		return err
	}
	header := "# AgentVault policy — first matching rule wins; unmatched hits defaults.action.\n# Docs: docs/SPEC.md §3.1. Validate changes with: agentvault policy check\n"
	if err := os.WriteFile(dest, append([]byte(header), data...), 0o600); err != nil {
		return err
	}
	p("")
	p("✓ wrote %s", dest)

	// 3. Install shims.
	if err := shim.EnsureInstalled(pol.Shims.Binaries); err != nil {
		p("! shim install: %v", err)
	} else {
		p("✓ shims installed in %s", paths.Shims())
	}

	// 4. Validate the written file end-to-end.
	if _, _, err := config.Load(dest); err != nil {
		return fmt.Errorf("self-check failed on %s: %w", dest, err)
	}
	p("✓ policy self-check passed")
	p("")
	p("Next:")
	p("  agentvault policy check")
	p("  agentvault run -- %s", orDefault(pol.Agent.Command, pol.Agent.Name))
	return nil
}

// verifyTelegram sends a test message; returns false with a printed
// reason on failure (init stays non-fatal by design).
func verifyTelegram(out interface{ Write([]byte) (int, error) }, token string, chatID int64) bool {
	ch := approval.NewTelegram(token, chatID, "")
	defer ch.Close()
	err := ch.SendTest("✅ AgentVault connected. Approval requests will arrive here.")
	if err != nil {
		fmt.Fprintf(out, "  ! Telegram test failed: %v\n", err)
		return false
	}
	return true
}

func ask(in *bufio.Reader, out interface{ Write([]byte) (int, error) }, prompt string) string {
	fmt.Fprint(out, prompt+" ")
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

func askYN(in *bufio.Reader, out interface{ Write([]byte) (int, error) }, prompt string, def bool) bool {
	suffix := " [y/N]:"
	if def {
		suffix = " [Y/n]:"
	}
	ans := strings.ToLower(ask(in, out, prompt+suffix))
	if ans == "" {
		return def
	}
	return ans == "y" || ans == "yes"
}

func orDefault(cmd []string, name string) string {
	if len(cmd) > 0 {
		return strings.Join(cmd, " ")
	}
	if name != "" && name != "my-agent" {
		return name
	}
	return "your-agent-command"
}
