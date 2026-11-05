package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/grants"
)

const grantUsage = `usage:
  heimdalld grant status                     the gate's state: access tier cap, approved hand-offs, open requests
  sudo heimdalld grant approve ID [--for 1h] allow one request (a hand-off lasts --for, at most 24h)
  sudo heimdalld grant deny ID               refuse it
  sudo heimdalld grant tier N                set the AI agent's access tier cap (0-3); switches the gate on
  sudo heimdalld grant revoke                end every approved hand-off now
  sudo heimdalld grant off                   switch the gate off (the agent goes back to its own setting)
Decisions are made by a person: root, at a terminal, never from a command an AI agent started (docs/GRANTS.md).`

func cmdGrant(args []string) int {
	st := grants.Default()
	if len(args) == 0 || args[0] == "status" || args[0] == "list" {
		return grantStatus(st)
	}
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	dur := fs.Duration("for", time.Hour, "how long an approved hand-off lasts (at most 24h)")
	action := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "heimdalld grant: deciding needs root (sudo)")
		return 1
	}
	if err := grants.Guard("/proc", grants.StdinIsTerminal()); err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld grant: refused:", err)
		return 1
	}
	by := os.Getenv("SUDO_USER")
	if by == "" {
		by = "root"
	}
	now := time.Now()
	switch {
	case (action == "approve" || action == "deny") && fs.NArg() == 1:
		id := fs.Arg(0)
		pending, err := st.Pending()
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld grant:", err)
			return 1
		}
		var req *grants.Request
		for i := range pending {
			if pending[i].ID == id {
				req = &pending[i]
			}
		}
		if req == nil {
			fmt.Fprintln(os.Stderr, "heimdalld grant: no open request", id, "(heimdalld grant status)")
			return 2
		}
		printRequest(*req)
		if action == "approve" {
			if req.Kind == grants.KindEscalation {
				fmt.Printf("The conversation and its files' text may be sent to %q for %s.\n", req.Detail, *dur)
			}
			if !confirm("Allow it? Type yes: ") {
				fmt.Println("nothing changed")
				return 1
			}
		}
		d, err := st.Decide(id, action == "approve", by, *dur, now)
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld grant:", err)
			return 1
		}
		fmt.Printf("%s: %s %s\n", d.Status, d.Kind, d.Detail)
		return 0
	case action == "tier" && fs.NArg() == 1:
		var n int
		if _, err := fmt.Sscan(fs.Arg(0), &n); err != nil {
			fmt.Fprintln(os.Stderr, grantUsage)
			return 2
		}
		if err := st.SetTier(n, by, now); err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld grant:", err)
			return 1
		}
		fmt.Printf("access tier cap: %d (the agent uses the lower of this and its own setting)\n", n)
		return 0
	case action == "revoke" && fs.NArg() == 0:
		if err := st.Revoke(by, now); err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld grant:", err)
			return 1
		}
		fmt.Println("every approved hand-off ended")
		return 0
	case action == "off" && fs.NArg() == 0:
		if !confirm("Switch the gate off? The AI agent then uses its own access setting and its own hand-off rules. Type yes: ") {
			return 1
		}
		if err := os.Remove(st.Decisions); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "heimdalld grant:", err)
			return 1
		}
		fmt.Println("gate off")
		return 0
	}
	fmt.Fprintln(os.Stderr, grantUsage)
	return 2
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line) == "yes"
}

func printRequest(r grants.Request) {
	fmt.Printf("request %s (%s, asked %d time(s), first %s)\n", r.ID, r.Time.Local().Format("2006-01-02 15:04"), r.Count, r.Kind)
	fmt.Printf("  wants:   %s %s\n", r.Kind, r.Detail)
	if r.SessionID != "" {
		fmt.Printf("  session: %s\n", r.SessionID)
	}
	fmt.Printf("  account: %d\n", r.UID)
	if r.Reason != "" {
		fmt.Printf("  reason (the agent's words, untrusted): %q\n", r.Reason)
	}
}

func grantStatus(st grants.Store) int {
	d, on, err := st.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld grant:", err)
		return 1
	}
	if !on {
		fmt.Println("gate: off (sudo heimdalld grant tier N switches it on)")
	} else {
		tier := "not set (read as 0, read-only)"
		if d.AccessTier != nil {
			tier = fmt.Sprint(*d.AccessTier)
		}
		fmt.Println("gate: on; access tier cap:", tier)
		for _, e := range d.Escalations {
			if e.Until.After(time.Now()) {
				s := e.SessionID
				if s == "" {
					s = "any session"
				}
				fmt.Printf("  hand-off to %s allowed for %s until %s (by %s)\n", e.Tier, s, e.Until.Local().Format("15:04"), e.By)
			}
		}
	}
	pending, err := st.Pending()
	if err != nil {
		fmt.Println("open requests: unreadable here (", err, "); try with sudo")
		return 0
	}
	if len(pending) == 0 {
		fmt.Println("no open requests")
	}
	for _, r := range grants.Sorted(pending) {
		printRequest(r)
	}
	return 0
}
