package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// integrateTarget describes one supported agent's integration surface.
type integrateTarget struct {
	name    string              // display name
	config  func(dir string) string // config file path for this agent
	mutate  func(cfg map[string]any, bin string) // apply agentvault changes
}

func newIntegrateCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "integrate <opencode|openclaw>",
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
				return fmt.Errorf("unknown agent %q (supported: opencode, openclaw)", args[0])
			}
			return integrate(cmd, t, dir, bin)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "working directory the agent may write to (default: cwd)")
	return cmd
}

func integrateTargets() map[string]integrateTarget {
	return map[string]integrateTarget{
		"opencode": {
			name: "OpenCode",
			config: func(dir string) string {
				return filepath.Join(dir, "opencode.json")
			},
			mutate: mutateOpenCode,
		},
		"openclaw": {
			name: "OpenClaw",
			config: func(dir string) string {
				return filepath.Join(dir, "opencode.json") // openclaw shares the format
			},
			mutate: mutateOpenCode,
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

func integrate(cmd *cobra.Command, t integrateTarget, dir, bin string) error {
	if dir == "" {
		dir, _ = os.Getwd()
	}
	cfgPath := t.config(dir)

	cfg := map[string]any{}
	if raw, err := os.ReadFile(cfgPath); err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("existing %s is not valid JSON: %w", cfgPath, err)
		}
	}
	t.mutate(cfg, bin)

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Backup an existing config before overwriting.
	if raw, err := os.ReadFile(cfgPath); err == nil {
		_ = os.WriteFile(cfgPath+".agentvault-backup", raw, 0o600)
	}
	if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ %s configured via %s\n", t.name, cfgPath)
	fmt.Fprintf(cmd.OutOrStdout(), "  - built-in write/edit/patch tools DISABLED\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  - file ops now flow through agentvault_fs (MCP) → policy + audit\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  - backup: %s.agentvault-backup\n", cfgPath)
	fmt.Fprintf(cmd.OutOrStdout(), "\nRestart the agent (inside 'agentvault run') to pick it up.\n")
	return nil
}
