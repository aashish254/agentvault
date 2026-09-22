package cli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// integrateTarget describes one supported agent's integration surface.
type integrateTarget struct {
	name    string                               // display name
	config  func(dir string) string              // config file path for this agent
	mutate  func(cfg map[string]any, bin string) // apply agentvault changes
	install func(dir, bin string)                // install hook plugins
	notes   []string                             // post-install report lines
}

func newIntegrateCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "integrate <opencode|openclaw|claude>",
		Short: "Wire an agent's file tools through AgentVault (MCP channel)",
		Long: `Writes the agent's config so that file edits route through an
AgentVault-wrapped MCP filesystem server instead of the agent's
built-in (invisible) tools. Built-in mutating tools (write/edit/patch)
are disabled; read-only tools stay enabled.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bin, err := os.Executable()
			if err != nil {
				return err
			}
			t, ok := integrateTargetsMap[args[0]]
			if !ok {
				return fmt.Errorf("unknown agent %q (supported: opencode, openclaw, claude)", args[0])
			}
			return integrate(cmd, t, dir, bin)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "working directory the agent may write to (default: cwd)")
	return cmd
}

func integrateTargets() map[string]integrateTarget {
	openCodeNotes := []string{
		"built-in write/edit/patch tools DISABLED",
		"file ops now flow through agentvault_fs (MCP) → policy + audit",
		"plugin gates every tool call (bash/read/write/edit/webfetch/...) via the session socket",
	}
	return map[string]integrateTarget{
		"opencode": {
			name: "OpenCode",
			config: func(dir string) string {
				return filepath.Join(dir, "opencode.json")
			},
			mutate:  mutateOpenCode,
			install: installOpenCodePlugin,
			notes:   openCodeNotes,
		},
		"openclaw": {
			name: "OpenClaw",
			config: func(dir string) string {
				return filepath.Join(dir, "opencode.json") // openclaw shares the format
			},
			mutate:  mutateOpenCode,
			install: installOpenCodePlugin,
			notes:   openCodeNotes,
		},
		"claude": {
			name: "Claude Code",
			config: func(dir string) string {
				return filepath.Join(dir, ".claude", "settings.json")
			},
			mutate: mutateClaude,
			notes: []string{
				"PreToolUse hook installed → EVERY tool call (Bash, Read, Write, Edit, WebFetch, MCP tools) is policy-checked",
				"blocked tools get the policy message back as agent feedback",
				"inside 'agentvault run', shims + egress + Seatbelt still apply underneath",
			},
		},
	}
}

var integrateTargetsMap map[string]integrateTarget

func init() { integrateTargetsMap = integrateTargets() }

// mutateOpenCode: disable built-in mutating tools, add the wrapped
// filesystem MCP server. Format per https://opencode.ai/docs.
func mutateOpenCode(cfg map[string]any, bin string) {
	cfg["$schema"] = "https://opencode.ai/config.json"
	cfg["tools"] = map[string]any{
		"write": false,
		"edit":  false,
		"patch": false,
	}
	cfg["mcp"] = map[string]any{
		"agentvault_fs": map[string]any{
			"type":    "local",
			"command": []string{bin, "mcp", "proxy", "--server", "filesystem", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."},
			"enabled": true,
		},
	}
}

// mutateClaude: install the PreToolUse hook in Claude Code's project
// settings. Every tool call (Bash, Read, Write, MCP tools, ...) pipes
// through `agentvault hook claude`; exit 2 blocks. Existing hooks are
// preserved; ours is appended once (idempotent).
func mutateClaude(cfg map[string]any, bin string) {
	hooks, _ := cfg["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)
	for _, e := range pre {
		if raw, err := json.Marshal(e); err == nil &&
			strings.Contains(string(raw), "agentvault hook claude") {
			return // already integrated
		}
	}
	entry := map[string]any{
		"matcher": "",
		"hooks": []any{
			map[string]any{"type": "command", "command": bin + " hook claude"},
		},
	}
	hooks["PreToolUse"] = append(pre, entry)
	cfg["hooks"] = hooks
}

func integrate(cmd *cobra.Command, t integrateTarget, dir, bin string) error {
	if dir == "" {
		dir, _ = os.Getwd()
	}
	cfgPath := t.config(dir)

	cfg := map[string]any{}
	// #nosec G304 -- the config path derives from the user-chosen project dir; reading it is the point.
	if raw, err := os.ReadFile(cfgPath); err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("existing %s is not valid JSON: %w", cfgPath, err)
		}
	}
	t.mutate(cfg, bin)
	if t.install != nil {
		t.install(dir, bin)
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Backup an existing config before overwriting.
	// #nosec G304 G703 -- cfgPath is the agent's own config file in the user-chosen dir.
	if raw, err := os.ReadFile(cfgPath); err == nil {
		_ = os.WriteFile(cfgPath+".agentvault-backup", raw, 0o600)
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ %s configured via %s\n", t.name, cfgPath)
	for _, n := range t.notes {
		fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", n)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  - backup: %s.agentvault-backup\n", cfgPath)
	fmt.Fprintf(cmd.OutOrStdout(), "\nRestart the agent (inside 'agentvault run') to pick it up.\n")
	return nil
}

//go:embed plugin/opencode/agentvault.ts
var openCodePluginTS string

// installOpenCodePlugin writes the AgentVault plugin into the project's
// .opencode/plugins/ dir. OpenCode auto-loads it at startup and every
// tool call (bash, read, write, edit) flows through the session socket.
func installOpenCodePlugin(dir, bin string) {
	plugDir := filepath.Join(dir, ".opencode", "plugins")
	if err := os.MkdirAll(plugDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "agentvault: plugin dir: %v\n", err)
		return
	}
	p := filepath.Join(plugDir, "agentvault.ts")
	if err := os.WriteFile(p, []byte(openCodePluginTS), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "agentvault: plugin write: %v\n", err)
	}
}
