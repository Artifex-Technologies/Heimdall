package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/Artifex-Technologies/Heimdall/internal/contain"
	"github.com/Artifex-Technologies/Heimdall/internal/trust"
)

func cmdContain(args []string) int {
	if len(args) == 0 {
		containUsage()
		return 2
	}
	marker := contain.MarkerPath
	if p := os.Getenv("HEIMDALL_CONTAIN_MARKER"); p != "" {
		marker = p // tests
	}
	needRoot := func() bool {
		if os.Geteuid() != 0 && os.Getenv("HEIMDALL_CONTAIN_MARKER") == "" {
			fmt.Fprintln(os.Stderr, "heimdalld contain: this needs root (sudo)")
			return false
		}
		return true
	}
	logger := log.New(os.Stderr, "heimdalld contain: ", 0)
	runner := func() *contain.Runner {
		return &contain.Runner{Sys: contain.Real{Trust: trust.Store{Dir: trust.DefaultDir}}, MarkerPath: marker,
			Log: func(s string) { logger.Println(s) }}
	}
	switch args[0] {
	case "status":
		m, locked := contain.ReadMarker(marker)
		cfg := contain.LoadConfig(contain.ConfigPath)
		if !locked {
			fmt.Println("Sarina: not contained")
		} else {
			fmt.Printf("Sarina: %s since %s\nreason: %s\n", m.Level, m.Since.Local().Format("2006-01-02 15:04"), m.Reason)
		}
		fmt.Printf("automatic containment: %s\nautomatic emergency: %s\n", onOff(cfg.AutoContain), onOff(cfg.AutoEmergency))
		if locked {
			return 1
		}
		return 0
	case "now":
		fs := flag.NewFlagSet("contain now", flag.ContinueOnError)
		reason := fs.String("reason", "contained by the owner", "why (kept in the lock)")
		escalate := fs.Bool("escalate", false, "when containment does not hold after a minute, go on to the emergency step")
		if fs.Parse(args[1:]) != nil || !needRoot() {
			return 2
		}
		if err := runner().Run(contain.Request{Reason: *reason}, contain.Config{}, *escalate); err != nil {
			logger.Println(err)
			return 1
		}
		return 0
	case "emergency":
		fs := flag.NewFlagSet("contain emergency", flag.ContinueOnError)
		yes := fs.Bool("yes", false, "really: this kills the desktop and every game and restarts the computer")
		reason := fs.String("reason", "emergency started by the owner", "why (kept in the lock)")
		if fs.Parse(args[1:]) != nil || !needRoot() {
			return 2
		}
		if !*yes {
			fmt.Fprintln(os.Stderr, "heimdalld contain emergency: this kills the desktop and every program on the graphics card, resets the card and restarts; add --yes")
			return 2
		}
		if err := runner().Emergency(*reason); err != nil {
			logger.Println(err)
			return 1
		}
		return 0
	case "run-request":
		// the root unit (heimdall-contain.service), when heimdalld asked
		if !needRoot() {
			return 2
		}
		b, err := os.ReadFile(contain.RequestPath)
		if err != nil {
			return 0
		}
		_ = os.Remove(contain.RequestPath)
		var req contain.Request
		if json.Unmarshal(b, &req) != nil || strings.TrimSpace(req.Reason) == "" {
			logger.Println("ignored an unreadable request")
			return 1
		}
		cfg := contain.LoadConfig(contain.ConfigPath)
		if !cfg.AutoContain {
			logger.Println("ignored a request: automatic containment is off (" + contain.ConfigPath + ")")
			return 0
		}
		req.Auto = true // whatever the file says: it came from heimdalld
		if len(req.Reason) > 300 {
			req.Reason = req.Reason[:300]
		}
		if err := runner().Run(req, cfg, false); err != nil {
			logger.Println(err)
			return 1
		}
		return 0
	case "release":
		// put back the approved behaviour files, then lift the lock (root: Settings asks for the password)
		if !needRoot() {
			return 2
		}
		st := trust.Store{Dir: trust.DefaultDir}
		if _, err := st.Load(); err == nil {
			back, err := st.Restore(nil)
			for _, r := range back {
				fmt.Printf("restored %s (it was %s)\n", r.Path, r.Why)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld contain: restoring failed, the lock stays:", err)
				return 1
			}
		} else {
			fmt.Println("no signed list (heimdalld trust init), so nothing to restore")
		}
		if err := contain.Release(marker); err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld contain:", err)
			return 1
		}
		if os.Getenv("HEIMDALL_CONTAIN_MARKER") == "" {
			_ = exec.Command("systemctl", "start", "ollama.service").Run()
		}
		fmt.Println("released: Sarina may start again")
		return 0
	}
	containUsage()
	return 2
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off (" + contain.ConfigPath + ")"
}

func containUsage() {
	fmt.Fprint(os.Stderr, strings.TrimLeft(`
heimdalld contain: stop a compromised AI agent (see docs/CONTAIN.md)
  heimdalld contain status                    is Sarina contained, and what may Heimdall do by itself
  heimdalld contain now [--reason R] [--escalate]
                                              unload the models, stop Sarina and lock her out (root); --escalate: the
                                              emergency step follows when that did not hold after a minute
  heimdalld contain emergency --yes           the last resort (root): restore the approved files, kill everything on the
                                              graphics card (games and the desktop too), reset the card, restart
  heimdalld contain release                   restore the approved files and lift the lock (root)
`, "\n"))
}
