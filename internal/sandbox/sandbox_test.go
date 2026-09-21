//go:build darwin

package sandbox

import (
	"strings"
	"testing"

	"github.com/aashish/agentvault/internal/config"
)

func testPolicy() *config.Policy {
	return &config.Policy{
		Version:  1,
		Defaults: config.DefaultsCfg{Action: config.EffectDeny},
		Rules: []config.Rule{
			{
				Name:   "protect-credentials",
				Match:  config.Match{Action: []config.ActionType{config.ActionFSRead, config.ActionFSWrite}, Path: []string{"/home/u/.ssh/**", "/home/u/.aws/**"}},
				Effect: config.EffectDeny,
			},
			{
				Name:   "workdir-writes",
				Match:  config.Match{Action: []config.ActionType{config.ActionFSWrite}, Path: []string{"/work/**"}},
				Effect: config.EffectAllow,
			},
		},
		Sandbox: config.SandboxCfg{Enabled: true},
		Egress:  config.EgressCfg{Listen: "127.0.0.1:0"},
	}
}

func testCtx() Context {
	return Context{Cwd: "/work", Home: "/home/u", ProxyAddr: "127.0.0.1:53111", HasEgress: true}
}

func TestGenerateGoldenStructure(t *testing.T) {
	p := Generate(testPolicy(), testCtx())
	sb := p.SBPL

	must := []string{
		"(version 1)",
		"(allow default)",
		`(deny file-read* file-write* (subpath "/home/u/.aws"))`,
		`(deny file-read* file-write* (subpath "/home/u/.ssh"))`,
		"(deny file-write*)",
		`(allow file-write* (subpath "/work"))`,
		`(allow file-write* (subpath "/private/tmp"))`, // /tmp canonicalized by resolveSymlinks
		"(deny network-outbound)",
		`(allow network-outbound (remote tcp "localhost:*"))`,
		`(allow network-outbound (remote tcp "127.0.0.1:53111"))`,
	}
	for _, m := range must {
		if !strings.Contains(sb, m) {
			t.Errorf("profile missing %q:\n%s", m, sb)
		}
	}
}

func TestDenyBeforeAllowWrite(t *testing.T) {
	// Seatbelt: later rules override. (deny file-write*) MUST precede the
	// allows, and deny paths must precede nothing they would shadow.
	sb := Generate(testPolicy(), testCtx()).SBPL
	denyIdx := strings.Index(sb, "(deny file-write*)")
	allowWorkIdx := strings.Index(sb, `(allow file-write* (subpath "/work"))`)
	denySSH := strings.Index(sb, `(subpath "/home/u/.ssh")`)
	if denyIdx < 0 || allowWorkIdx < 0 || denySSH < 0 {
		t.Fatal("missing rules")
	}
	if denySSH >= denyIdx || denyIdx >= allowWorkIdx {
		t.Fatalf("rule order wrong — seatbelt later-wins semantics would break:\n%s", sb)
	}
}

func TestNoEgressNoNetworkDeny(t *testing.T) {
	ctx := testCtx()
	ctx.HasEgress = false
	sb := Generate(testPolicy(), ctx).SBPL
	if strings.Contains(sb, "network-outbound") {
		t.Fatalf("network rules must not appear without egress:\n%s", sb)
	}
}

func TestRestrictNetworkFalse(t *testing.T) {
	pol := testPolicy()
	off := false
	pol.Sandbox.RestrictNetwork = &off
	sb := Generate(pol, testCtx()).SBPL
	if strings.Contains(sb, "deny network-outbound") {
		t.Fatal("restrict_network=false must skip the network deny")
	}
}

func TestGlobToSBPL(t *testing.T) {
	cases := map[string]string{
		"/a/b/**":       `(subpath "/a/b")`,
		"/a/b/file.txt": `(literal "/a/b/file.txt")`,
		"/a/*/c":        `(regex "^/a/[^/]*/c$")`,
		"/a/**/c":       `(regex "^/a/.*/c$")`,
	}
	for in, want := range cases {
		if got := toSBPLFilter(in); got != want {
			t.Errorf("toSBPLFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNoDenyPathsWarns(t *testing.T) {
	pol := testPolicy()
	pol.Rules = pol.Rules[1:] // drop credential rule
	p := Generate(pol, testCtx())
	found := false
	for _, n := range p.Notes {
		if strings.Contains(n, "warning") {
			found = true
		}
	}
	if !found {
		t.Fatal("must warn when sandbox has no deny paths")
	}
}
