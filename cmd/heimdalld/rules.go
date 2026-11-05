package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/grants"
	"github.com/Artifex-Technologies/Heimdall/internal/immunity"
)

const ruleUsage = `usage:
  heimdalld immunity rule list                      the YARA rule drafts and their state
  heimdalld immunity rule show ID                   one draft: the rule, who drafted it, its test
  sudo heimdalld immunity rule draft SHA256 FILE    keep a rule you wrote for a held sample (Sarina drafts through the API)
  sudo heimdalld immunity rule test ID [--fp DIR]... match it against the sample (must) and this computer's programs (must not)
  sudo heimdalld immunity rule approve ID           ClamAV loads it from now on (only after a passing test of this exact text)
  sudo heimdalld immunity rule reject ID            refuse it; an approved rule is removed from ClamAV
See docs/IMMUNITY.md, "Rules".`

func cmdRule(args []string, st immunity.Store) int {
	r := immunity.DefaultRules()
	if p := os.Getenv("HEIMDALL_RULE_DRAFTS"); p != "" { // tests
		r.Path = p
	}
	if d := os.Getenv("HEIMDALL_RULES_DIR"); d != "" {
		r.RulesDir = d
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, ruleUsage)
		return 2
	}
	fs := flag.NewFlagSet("rule", flag.ContinueOnError)
	var fp listFlag
	fs.Var(&fp, "fp", "a folder of this computer's own programs the rule must not match (repeatable; default /usr/bin, /usr/local/bin, /usr/lib/systemd)")
	if err := fs.Parse(flagsFirst(args[1:])); err != nil {
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "heimdalld immunity rule:", err); return 1 }
	find := func(id string) (immunity.Rule, bool) {
		rs, _ := r.Load()
		for _, x := range rs {
			if x.ID == id {
				return x, true
			}
		}
		return immunity.Rule{}, false
	}
	switch {
	case args[0] == "list":
		rs, err := r.Load()
		if err != nil {
			return fail(err)
		}
		if len(rs) == 0 {
			fmt.Println("no rule drafts")
		}
		for _, x := range rs {
			fmt.Printf("%s  %-9s %-40s sample %s  %s\n", x.ID, x.Status, x.Name, x.SampleSHA[:12], x.Time.Local().Format("2006-01-02 15:04"))
		}
		return 0
	case args[0] == "show" && fs.NArg() == 1:
		x, ok := find(fs.Arg(0))
		if !ok {
			return fail(fmt.Errorf("no draft %s", fs.Arg(0)))
		}
		fmt.Printf("draft %s (%s), rule %s, for sample %s, from account %d at %s\n", x.ID, x.Status, x.Name, x.SampleSHA, x.UID, x.Time.Local().Format("2006-01-02 15:04"))
		if x.Note != "" {
			fmt.Printf("note (the drafter's words, untrusted): %q\n", x.Note)
		}
		fmt.Println("---\n" + strings.TrimRight(x.Text, "\n") + "\n---")
		if t := x.Test; t != nil {
			fmt.Printf("test %s: matched the sample: %v; matched %d of this computer's files in %s", t.Time.Local().Format("2006-01-02 15:04"), t.MatchedSample, t.FPCount, strings.Join(t.Scanned, ", "))
			if t.Error != "" {
				fmt.Printf("; error: %s", t.Error)
			}
			fmt.Println()
			for _, p := range t.FalsePositives {
				fmt.Println("  matched:", p)
			}
		}
		return 0
	}
	// everything below needs the samples (root) or decides (the owner)
	if os.Geteuid() != 0 && os.Getenv("HEIMDALL_IMMUNITY_DIR") == "" {
		return fail(fmt.Errorf("this needs root (sudo)"))
	}
	by := os.Getenv("SUDO_USER")
	if by == "" {
		by = "root"
	}
	now := time.Now()
	switch {
	case args[0] == "draft" && fs.NArg() == 2:
		b, err := os.ReadFile(fs.Arg(1))
		if err != nil {
			return fail(err)
		}
		es, _ := st.Load()
		sha := ""
		for _, e := range es {
			if strings.HasPrefix(e.SHA256, fs.Arg(0)) && len(fs.Arg(0)) >= 8 {
				sha = e.SHA256
			}
		}
		if sha == "" {
			return fail(fmt.Errorf("no held sample %s (heimdalld immunity list)", fs.Arg(0)))
		}
		d, err := r.Draft(sha, string(b), "written by "+by, 0, now)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("draft %s kept; next: sudo heimdalld immunity rule test %s\n", d.ID, d.ID)
		return 0
	case args[0] == "test" && fs.NArg() == 1:
		roots := []string(fp)
		if len(roots) == 0 {
			roots = immunity.DefaultFPRoots
		}
		fmt.Println("testing against the sample and", strings.Join(roots, ", "), "(this reads every file there; about half a minute for /usr/bin)")
		x, err := r.Test(fs.Arg(0), st, roots, immunity.ClamRuleScan, now)
		if err != nil {
			return fail(err)
		}
		t := x.Test
		fmt.Printf("%s: matched the sample: %v; matched %d of this computer's files", x.Status, t.MatchedSample, t.FPCount)
		if t.Error != "" {
			fmt.Printf("; error: %s", t.Error)
		}
		fmt.Println()
		for _, p := range t.FalsePositives {
			fmt.Println("  matched:", p)
		}
		if x.Status == immunity.RuleTested {
			fmt.Println("next: sudo heimdalld immunity rule approve", x.ID)
			return 0
		}
		return 1
	case (args[0] == "approve" || args[0] == "reject") && fs.NArg() == 1:
		if err := grants.Guard("/proc", grants.StdinIsTerminal()); err != nil {
			return fail(fmt.Errorf("refused: %v", err))
		}
		x, ok := find(fs.Arg(0))
		if !ok {
			return fail(fmt.Errorf("no draft %s", fs.Arg(0)))
		}
		if args[0] == "approve" {
			fmt.Println("---\n" + strings.TrimRight(x.Text, "\n") + "\n---")
			if !confirm("ClamAV will report every file this rule matches as malware. Approve it? Type yes: ") {
				fmt.Println("nothing changed")
				return 1
			}
			x, err := r.Approve(x.ID, by, now)
			if err != nil {
				return fail(err)
			}
			fmt.Println("approved; ClamAV loads", x.Installed, "on its next start or scan (YARA."+x.Name+")")
			return 0
		}
		if _, err := r.Reject(x.ID, by, now); err != nil {
			return fail(err)
		}
		fmt.Println("rejected")
		return 0
	}
	fmt.Fprintln(os.Stderr, ruleUsage)
	return 2
}
