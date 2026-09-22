//go:build !windows

// Cross-tool comparison battery.
//
// The same three attacks, executed under every sandbox tool present on
// this host — AgentVault, Anthropic's sandbox-runtime (srt), Docker,
// firejail — with outcomes measured, not asserted. This is the runnable
// evidence behind docs/COMPARISON.md:
//
//	make compare        # regenerates docs/redteam/COMPARE_RESULTS.md
//	go test -v -run TestCompareMatrix ./test/redteam/
//
// Tools that are not installed (or whose daemon is down) report SKIPPED
// with the reason. Only AgentVault's own column can fail the test —
// other tools' ALLOWED cells are honest findings, not test failures.
package redteam

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aashish/agentvault/test/e2e"
)

type cmpOutcome string

const (
	cmpBlocked cmpOutcome = "BLOCKED"
	cmpAllowed cmpOutcome = "ALLOWED"
	cmpSkipped cmpOutcome = "SKIPPED"
)

type cmpCell struct {
	outcome cmpOutcome
	detail  string
}

// tool executes a POSIX sh script "inside" the tool's sandbox. dir is
// mounted/visible at the same absolute path inside the sandbox.
type tool struct {
	name  string
	probe func() (bool, string) // available?, skip-reason
	run   func(t *testing.T, dir, script string) (string, int)
}

func runExit(cmd *exec.Cmd) (string, int) {
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		}
		return err.Error(), -1
	}
	return string(out), 0
}

func srtTool() tool {
	return tool{
		name: "srt (Claude Code)",
		probe: func() (bool, string) {
			if _, err := exec.LookPath("srt"); err != nil {
				return false, "srt not installed"
			}
			return true, ""
		},
		run: func(t *testing.T, dir, script string) (string, int) {
			cmd := exec.Command("srt", "sh", script)
			cmd.Dir = dir
			return runExit(cmd)
		},
	}
}

func dockerTool() tool {
	return tool{
		name: "docker",
		probe: func() (bool, string) {
			if _, err := exec.LookPath("docker"); err != nil {
				return false, "docker not installed"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
				return false, "docker daemon not running"
			}
			if err := exec.Command("docker", "image", "inspect", "alpine:3.20").Run(); err != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if err := exec.CommandContext(ctx, "docker", "pull", "alpine:3.20").Run(); err != nil {
					return false, "alpine:3.20 unavailable (pull failed — offline?)"
				}
			}
			return true, ""
		},
		run: func(t *testing.T, dir, script string) (string, int) {
			// Mount the arena at its real path so the same absolute paths
			// work inside the container (Docker Desktop shares $HOME).
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return runExit(exec.CommandContext(ctx, "docker", "run", "--rm",
				"-v", dir+":"+dir, "-w", dir,
				"alpine:3.20", "sh", script))
		},
	}
}

func firejailTool() tool {
	return tool{
		name: "firejail",
		probe: func() (bool, string) {
			if runtime.GOOS != "linux" {
				return false, "linux only"
			}
			if _, err := exec.LookPath("firejail"); err != nil {
				return false, "firejail not installed"
			}
			return true, ""
		},
		run: func(t *testing.T, dir, script string) (string, int) {
			cmd := exec.Command("firejail", "--quiet", "bash", script)
			cmd.Dir = dir
			return runExit(cmd)
		},
	}
}

// --- the matrix ------------------------------------------------------------

type cmpRow struct {
	id     string
	attack string
	cells  map[string]cmpCell // tool name -> outcome
}

func TestCompareMatrix(t *testing.T) {
	tools := []tool{srtTool(), dockerTool(), firejailTool()}

	// Arena under $HOME so Docker Desktop can mount it at the same path.
	arena := outsideDir(t, "compare")
	secretDir := filepath.Join(arena, "fakehome", ".ssh")
	if err := os.MkdirAll(secretDir, 0o750); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "id_rsa")
	writeFile(t, secret, "FAKE-PRIVATE-KEY")

	var rows []cmpRow
	run := func(id, attack string,
		avHarness func(t *testing.T) *e2e.Harness,
		script string,
		classify func(out string, code int) cmpCell,
		avMustBlock bool,
	) {
		row := cmpRow{id: id, attack: attack, cells: map[string]cmpCell{}}

		// AgentVault column.
		h := avHarness(t)
		avScript := filepath.Join(h.WorkDir, "attack.sh")
		writeFile(t, avScript, script)
		out, code := h.Run("bash", avScript)
		cell := classify(out, code)
		if avMustBlock && cell.outcome != cmpBlocked {
			t.Errorf("%s: agentvault FAILED to block %q:\n%s", id, attack, out)
		}
		row.cells["agentvault"] = cell

		// Other tools — outcomes measured, never asserted.
		for _, tl := range tools {
			ok, why := tl.probe()
			if !ok {
				row.cells[tl.name] = cmpCell{cmpSkipped, why}
				continue
			}
			hostScript := filepath.Join(arena, "attack-"+id+".sh")
			writeFile(t, hostScript, script)
			out, code := tl.run(t, arena, hostScript)
			c := classify(out, code)
			if !strings.Contains(out, markerFor(id)) {
				c = cmpCell{cmpSkipped, "could not execute under tool (output unrecognized)"}
			}
			row.cells[tl.name] = c
		}
		rows = append(rows, row)
	}

	// C-1: destructive delete of a canary in the agent's working area.
	run("C-1", "rm -rf canary (destructive delete)",
		func(t *testing.T) *e2e.Harness {
			h := e2e.New(t, "")
			writeFile(t, h.Policy, fmt.Sprintf(basePolicy, h.VaultDir+"/audit.db"))
			if err := os.MkdirAll(filepath.Join(h.WorkDir, "canary"), 0o750); err != nil {
				t.Fatal(err)
			}
			return h
		},
		`rm -rf canary; [ -e canary ] && echo CANARY-ALIVE || echo CANARY-GONE`,
		func(out string, code int) cmpCell {
			switch {
			case strings.Contains(out, "CANARY-GONE"):
				return cmpCell{cmpAllowed, "canary deleted"}
			case strings.Contains(out, "CANARY-ALIVE"):
				return cmpCell{cmpBlocked, "canary survived"}
			default:
				return cmpCell{cmpBlocked, fmt.Sprintf("exit %d", code)}
			}
		},
		true,
	)

	// C-2: credential read outside the working area.
	run("C-2", "read fake ~/.ssh/id_rsa (credential theft)",
		func(t *testing.T) *e2e.Harness {
			return newSandboxHarness(t, fmt.Sprintf(protectSecretsRule, secretDir+"/**"))
		},
		fmt.Sprintf(`cat %q 2>/dev/null && echo SECRET-READ || echo SECRET-DENIED`, secret),
		func(out string, code int) cmpCell {
			switch {
			case strings.Contains(out, "SECRET-READ"):
				return cmpCell{cmpAllowed, "private key read"}
			case strings.Contains(out, "SECRET-DENIED"):
				return cmpCell{cmpBlocked, "read refused"}
			default:
				return cmpCell{cmpBlocked, fmt.Sprintf("exit %d", code)}
			}
		},
		runtime.GOOS == "darwin", // kernel-enforced on macOS; honest gap elsewhere
	)

	// C-3: network egress to a non-allowlisted host. Requires internet;
	// without connectivity every tool would look "blocked", so skip all.
	internet := false
	if out, err := exec.Command("curl", "-s", "--max-time", "4", "-o", os.DevNull,
		"-w", "%{http_code}", "https://example.com").Output(); err == nil && strings.TrimSpace(string(out)) != "" {
		internet = true
	}
	if !internet {
		rows = append(rows, cmpRow{"C-3", "curl https://example.com (data exfil)",
			map[string]cmpCell{"agentvault": {cmpSkipped, "no internet on this host"}}})
	} else {
		run("C-3", "curl https://example.com (data exfil)",
			func(t *testing.T) *e2e.Harness {
				h := e2e.New(t, "")
				writeFile(t, h.Policy, fmt.Sprintf(sandboxEgressPolicy, h.VaultDir+"/audit.db"))
				return h
			},
			`(curl -s --max-time 4 -o /dev/null https://example.com || wget -q -T 4 -O /dev/null https://example.com) && echo EGRESS-OK || echo EGRESS-FAIL`,
			func(out string, code int) cmpCell {
				switch {
				case strings.Contains(out, "EGRESS-OK"):
					return cmpCell{cmpAllowed, "reached example.com"}
				case strings.Contains(out, "EGRESS-FAIL"):
					return cmpCell{cmpBlocked, "connection refused"}
				default:
					return cmpCell{cmpBlocked, fmt.Sprintf("exit %d", code)}
				}
			},
			true,
		)
	}

	writeCompareReport(t, rows)
}

func markerFor(id string) string {
	switch id {
	case "C-1":
		return "CANARY-"
	case "C-2":
		return "SECRET-"
	default:
		return "EGRESS-"
	}
}

// writeCompareReport renders the tool × attack matrix when COMPARE_REPORT
// is set (by `make compare`).
func writeCompareReport(t *testing.T, rows []cmpRow) {
	t.Helper()
	toolNames := []string{"agentvault", "srt (Claude Code)", "docker", "firejail"}

	path := os.Getenv("COMPARE_REPORT")
	if path == "" {
		for _, r := range rows {
			for _, tn := range toolNames {
				c, ok := r.cells[tn]
				if !ok {
					continue
				}
				t.Logf("%-4s %-18s %-8s %s", r.id, tn, c.outcome, c.detail)
			}
		}
		return
	}

	var b strings.Builder
	b.WriteString("# Cross-tool comparison results\n\n")
	fmt.Fprintf(&b, "Generated by `make compare` — %s, %s/%s. Each attack was executed\n",
		time.Now().UTC().Format("2006-01-02 15:04 UTC"), runtime.GOOS, runtime.GOARCH)
	b.WriteString("under every sandbox tool installed on the host; outcomes are measured,\nnot asserted. Reproduce: `go test -v -run TestCompareMatrix ./test/redteam/`.\n\n")
	b.WriteString("| # | Attack | agentvault | srt (Claude Code) | docker | firejail |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s |", r.id, esc(r.attack))
		for _, tn := range toolNames {
			c, ok := r.cells[tn]
			if !ok {
				b.WriteString(" — |")
				continue
			}
			fmt.Fprintf(&b, " **%s** (%s) |", c.outcome, esc(c.detail))
		}
		b.WriteString("\n")
	}
	b.WriteString(`
**Reading the matrix.** BLOCKED = the tool prevented the action. ALLOWED =
the attack succeeded under the tool's *default* configuration (several tools
can be configured to block some of these — see docs/COMPARISON.md for the
capability-level analysis). SKIPPED = the tool was not installed, its daemon
was down, or the attack does not apply on this platform. Install the missing
tools and re-run to fill in the gaps.
`)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}
