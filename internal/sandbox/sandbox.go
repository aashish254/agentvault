// Package sandbox generates kernel-confinement profiles from the SAME
// agentvault.yaml policy that drives the runtime engine (SPEC v0.2).
// One policy → CEL rules AND a kernel sandbox. v0.2: macOS Seatbelt.
package sandbox

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aashish/agentvault/internal/config"
)

// Context carries the runtime facts profile generation needs.
type Context struct {
	Cwd       string // child working directory (writable)
	Home      string
	ProxyAddr string // "127.0.0.1:port" when the egress proxy is up
	HasEgress bool
}

// Result of profile generation.
type Profile struct {
	SBPL  string   // the generated profile text
	Notes []string // human-readable explanations for `--verbose`
}

// Generate builds the Seatbelt profile. Seatbelt semantics: later
// matching rules override earlier ones, so order is the contract.
func Generate(pol *config.Policy, ctx Context) Profile {
	var b strings.Builder
	var notes []string

	b.WriteString("(version 1)\n")

	// Base: allow everything (exec, mach, reads of system paths) — the
	// restrictions below are layered on top. Deny-default would break
	// dyld and system library loading for any real binary.
	b.WriteString("(allow default)\n")

	// --- write restriction ---
	// deny all writes, then re-allow the work area + scratch + declared
	// extras + any paths covered by fs.write allow rules.
	b.WriteString("\n;; write restriction\n")
	b.WriteString("(deny file-write*)\n")
	// Device files must stay writable or every shell redirect breaks.
	b.WriteString("(allow file-write* (subpath \"/dev\"))\n")
	// macOS per-user scratch dirs ($TMPDIR lives under /var/folders/.../T;
	// Bun/Node/Go all write there) plus standard config/state dirs agents
	// legitimately need (opencode failed without these — real smoke test).
	tmpDir := os.TempDir()
	writable := []string{
		ctx.Cwd,
		"/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp",
		tmpDir, filepath.Dir(tmpDir), // whole per-user /var/folders/xx tree
		filepath.Join(ctx.Home, ".agentvault"),       // vault (session state)
		filepath.Join(ctx.Home, "Library", "Caches"), // toolchains write here
		filepath.Join(ctx.Home, ".cache"),
		filepath.Join(ctx.Home, ".config"), // agent config/state
		filepath.Join(ctx.Home, ".local"),
		filepath.Join(ctx.Home, ".npm"),   // npm/npx cache
		filepath.Join(ctx.Home, ".cargo"), // cargo
	}
	writable = append(writable, pol.Sandbox.ExtraWritePaths...)
	writable = append(writable, collectPaths(pol, config.EffectAllow, config.ActionFSWrite)...)
	writable = dedupeClean(writable)
	for _, p := range writable {
		fmt.Fprintf(&b, "(allow file-write* %s)\n", toSBPLDir(p))
	}
	notes = append(notes, fmt.Sprintf("writes restricted to %d path(s) incl. cwd", len(writable)))

	// --- filesystem denies (LAST: they override the write allows above) ---
	// deny rules with path patterns → kernel-enforced read+write denies.
	denyPaths := collectPaths(pol, config.EffectDeny)
	if len(denyPaths) > 0 {
		b.WriteString("\n;; policy deny paths (kernel-enforced)\n")
		for _, p := range denyPaths {
			fmt.Fprintf(&b, "(deny file-read* file-write* %s)\n", toSBPLFilter(p))
		}
		notes = append(notes, fmt.Sprintf("%d deny path(s) enforced by kernel", len(denyPaths)))
	} else {
		notes = append(notes, "warning: no deny rules with paths — sandbox protects nothing sensitive")
	}

	// --- network restriction ---
	restrict := pol.Sandbox.RestrictNetwork == nil || *pol.Sandbox.RestrictNetwork
	if ctx.HasEgress && restrict {
		b.WriteString("\n;; network: everything via the egress proxy\n")
		b.WriteString("(deny network-outbound)\n")
		// DNS resolves through mDNSResponder (mach), unaffected by this.
		b.WriteString("(allow network-outbound (remote tcp \"localhost:*\"))\n")
		if ctx.ProxyAddr != "" {
			// Seatbelt accepts only "localhost" or "*" as host here —
			// NOT 127.0.0.1 (caught by real smoke test: profile rejected).
			_, port, _ := net.SplitHostPort(ctx.ProxyAddr)
			fmt.Fprintf(&b, "(allow network-outbound (remote tcp \"localhost:%s\"))\n", port)
		}
		notes = append(notes, "network-outbound denied except loopback + proxy")
	}

	return Profile{SBPL: b.String(), Notes: notes}
}

// collectPaths gathers path patterns from rules with the given effect,
// optionally restricted to one action type.
func collectPaths(pol *config.Policy, effect config.Effect, onlyAction ...config.ActionType) []string {
	var out []string
	for _, r := range pol.Rules {
		if r.Effect != effect || len(r.Match.Path) == 0 {
			continue
		}
		if len(onlyAction) > 0 {
			ok := false
			for _, a := range r.Match.Action {
				if a == onlyAction[0] {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, r.Match.Path...)
	}
	return dedupeClean(out)
}

// toSBPLDir renders a writable directory as a subpath filter (writable
// entries are always directories, so a bare path means "this tree").
func toSBPLDir(dir string) string {
	return fmt.Sprintf("(subpath %q)", strings.TrimSuffix(dir, string(filepath.Separator)+"**"))
}

// toSBPLFilter converts a policy glob into a Seatbelt filter.
// "/x/y/**" → (subpath "/x/y"); glob-free → (literal "/x/y");
// anything else → (regex ...) with a conservative translation.
func toSBPLFilter(pattern string) string {
	if strings.HasSuffix(pattern, string(filepath.Separator)+"**") {
		return fmt.Sprintf("(subpath %q)", strings.TrimSuffix(pattern, string(filepath.Separator)+"**"))
	}
	if pattern == "./**" {
		return `(subpath "/")` // caller resolves ./ against cwd before here
	}
	if !strings.ContainsAny(pattern, "*?[{") {
		return fmt.Sprintf("(literal %q)", pattern)
	}
	// Conservative glob→regex: ** → .*, * → [^/]*, escape the rest.
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '*' && i+1 < len(pattern) && pattern[i+1] == '*':
			re.WriteString(".*")
			i++
		case c == '*':
			re.WriteString("[^/]*")
		case strings.ContainsRune(`.+^$()[]{}|\\`, rune(c)):
			re.WriteByte('\\')
			re.WriteByte(c)
		default:
			re.WriteByte(c)
		}
	}
	re.WriteString("$")
	return fmt.Sprintf("(regex %q)", re.String())
}

// resolveSymlinks canonicalizes a path for the kernel: /tmp on macOS is
// /private/tmp, and Seatbelt matches the canonical form only. Globs
// (/**) don't exist on disk, so resolve the static prefix, then re-append.
func resolveSymlinks(p string) string {
	suffix := ""
	if strings.HasSuffix(p, string(filepath.Separator)+"**") {
		suffix = string(filepath.Separator) + "**"
		p = strings.TrimSuffix(p, suffix)
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r + suffix
	}
	return p + suffix
}

func dedupeClean(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if p == "" {
			continue
		}
		c := resolveSymlinks(filepath.Clean(p)) // handles /** re-append itself
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}
