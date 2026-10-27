package remoteaccess

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTheBuiltinCatalogLoadsAndMatches(t *testing.T) {
	c := Builtin()
	if p := c.MatchPackage("tailscale"); p == nil || p.ID != "tailscale" {
		t.Fatal("package tailscale")
	}
	if p := c.MatchIface("zt5u4nvqrn"); p == nil || p.ID != "zerotier" {
		t.Fatal("ZeroTier interface pattern")
	}
	if c.MatchIface("wlp7s0") != nil || c.MatchPackage("bash") != nil {
		t.Fatal("ordinary things matched")
	}
	if p := c.MatchExe("/usr/bin/tailscaled", ""); p == nil || p.ID != "tailscale" {
		t.Fatal("tailscaled by file name")
	}
	if p := c.MatchExe("/tmp/.x/tailscaled (deleted)", ""); p == nil {
		t.Fatal("a deleted program is still named")
	}
	if p := c.MatchGoModules([]string{"example.com/x", "tailscale.com/ipn"}); p == nil || p.ID != "tailscale" {
		t.Fatal("a Go program that embeds tailscale.com")
	}
	for _, p := range c.Providers {
		if (p.Kind == "c2") == p.Approvable() {
			t.Fatalf("%s: c2 must never be approvable, others always", p.ID)
		}
	}
}

func TestParseRefusesUnusableEntries(t *testing.T) {
	for _, bad := range []string{`{"providers":[{"id":"","kind":"tunnel","exes":["x"]}]}`, `{"providers":[{"id":"a","kind":"tunnel"}]}`,
		`{"providers":[{"id":"a","kind":"tunnel","exes":["x"]},{"id":"a","kind":"tunnel","exes":["y"]}]}`, `not json`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// A Go tool renamed to something innocent is still recognised from its build info: the test binary itself, copied under a
// harmless name, against a catalog entry for this module.
func TestARenamedGoProgramIsRecognisedByItsBuildInfo(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	renamed := filepath.Join(t.TempDir(), "systemd-helper")
	in, _ := os.Open(self)
	out, _ := os.Create(renamed)
	io.Copy(out, in)
	in.Close()
	out.Close()
	c, _ := Parse([]byte(`{"providers":[{"id":"selftest","kind":"tunnel","go_modules":["github.com/Artifex-Technologies/Heimdall"]}]}`))
	id := &Identifier{Catalog: c}
	p, sig := id.Identify(renamed, "systemd-helper")
	if p == nil || p.ID != "selftest" || sig != "gomod" {
		t.Fatalf("not recognised: %v %q", p, sig)
	}
	if p, _ := (&Identifier{Catalog: Builtin()}).Identify(renamed, "systemd-helper"); p != nil {
		t.Fatalf("an ordinary Go program matched %s", p.ID)
	}
}

func TestAProgramThatOnlyContainsAToolsCodeIsToldApart(t *testing.T) {
	c := Builtin()
	if r := classify(c, []string{"github.com/jpillora/chisel"}, nil); r.p == nil || r.sig != "gomod" {
		t.Fatalf("the tool itself: %+v", r)
	}
	if r := classify(c, []string{"example.com/app"}, []string{"golang.org/x/net", "tailscale.com"}); r.p == nil || r.p.ID != "tailscale" || r.sig != "gomod-dep" {
		t.Fatalf("an embedding program: %+v", r)
	}
	if r := classify(c, []string{"example.com/app"}, []string{"golang.org/x/net"}); r.p != nil {
		t.Fatalf("an ordinary program: %+v", r)
	}
}

func TestApprovalsAreReadAgainWhenTheFileChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approved.json")
	a := &Approvals{Path: path}
	if a.Approved("tailscale") {
		t.Fatal("nothing approved yet")
	}
	if _, err := SetApproved(path, "tailscale", true); err != nil {
		t.Fatal(err)
	}
	if !a.Approved("tailscale") || a.Approved("ngrok") {
		t.Fatal("approval not read")
	}
	SetApproved(path, "tailscale", false)
	later := time.Now().Add(time.Second) // the same second on a coarse clock: make the change visible
	os.Chtimes(path, later, later)
	if a.Approved("tailscale") {
		t.Fatal("forgetting not read")
	}
}
