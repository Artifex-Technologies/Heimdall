package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
	"github.com/Artifex-Technologies/Heimdall/internal/pkgaudit"
)

// cmdOrigin prints where addresses belong, from the offline IP database (nothing is looked up online).
func cmdOrigin(args []string) int {
	fs := flag.NewFlagSet("origin", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/heimdall/config.json", "config file (for ip_databases)")
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: heimdalld origin [--config PATH] IP...")
		return 2
	}
	cfg := config.Default()
	if c, err := config.Load(*cfgPath); err == nil {
		cfg = c
	}
	r := ipintel.NewResolver(cfg.IPDatabases...)
	threats := ipintel.NewLists(cfg.ThreatListDir)
	if !r.Available() {
		fmt.Fprintln(os.Stderr, "heimdalld: no IP database yet (run heimdall-intel-update); only private and reserved addresses can be named")
	}
	rc := 0
	for _, a := range fs.Args() {
		ip := net.ParseIP(a)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "%s: not an IP address\n", a)
			rc = 1
			continue
		}
		line := fmt.Sprintf("%s  %s", ip, r.Lookup(ip))
		if l := threats.Match(ip); len(l) > 0 {
			line += "  [on threat lists: " + strings.Join(l, ", ") + "]"
		}
		fmt.Println(line)
	}
	return rc
}

// cmdIPDBCheck opens database files and says what they are; exit 1 if one is not a usable database. heimdall-intel-update
// runs it on a download before it replaces the file in use.
func cmdIPDBCheck(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: heimdalld ipdb-check FILE...")
		return 2
	}
	rc := 0
	for _, p := range args {
		db, err := ipintel.Open(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", p, err)
			rc = 1
			continue
		}
		// a database that cannot place a well-known public address is not one this can use
		m, err := db.Lookup(net.ParseIP("8.8.8.8"))
		if err != nil || m == nil {
			fmt.Fprintf(os.Stderr, "%s: opens, but knows nothing about 8.8.8.8 (%v)\n", p, err)
			rc = 1
			continue
		}
		fmt.Printf("%s: %s, built %s, 8.8.8.8 is %s\n", p, db.Type, time.Unix(int64(db.BuildEpoch), 0).UTC().Format("2006-01-02"), ipintel.FromRecord(m))
	}
	return rc
}

// cmdIntelCheck validates a downloaded threat list (at least a few entries, all parseable) or security tracker file.
func cmdIntelCheck(args []string) int {
	if (len(args) == 3 || len(args) == 4) && args[0] == "kernel" {
		// osv.dev's Linux archive in (and CISA's exploited list, optional), the small list the daemon reads out (only written when
		// the archive is whole)
		var exploited map[string]bool
		if len(args) == 4 {
			var err error
			if exploited, err = kernelaudit.Exploited(args[3]); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v (the list is made without it)\n", args[3], err)
			}
		}
		f, err := kernelaudit.Compact(args[1], exploited)
		if err == nil {
			var b []byte
			b, err = json.Marshal(f)
			if err == nil {
				tmp := args[2] + ".tmp"
				if err = os.WriteFile(tmp, b, 0o640); err == nil {
					err = os.Rename(tmp, args[2])
				}
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", args[1], err)
			return 1
		}
		fmt.Printf("%s: %d kernel CVE records\n", args[2], len(f.Vulns))
		return 0
	}
	if len(args) != 2 && !(len(args) == 3 && args[0] == "list") {
		fmt.Fprintln(os.Stderr, "usage: heimdalld intel-check list FILE [LAST-GOOD] | tracker FILE | kernel ARCHIVE OUT [EXPLOITED]")
		return 2
	}
	b, err := os.ReadFile(args[1])
	if err == nil {
		switch args[0] {
		case "list":
			var l *ipintel.List
			if l, err = ipintel.ParseList("check", b); err == nil && l.Len() < 10 {
				err = errors.New("fewer than 10 entries: probably an error page, not a list")
			}
			if err == nil && len(args) == 3 {
				if pb, perr := os.ReadFile(args[2]); perr == nil {
					if prev, perr := ipintel.ParseList("last", pb); perr == nil {
						err = ipintel.CheckUpdate(prev, l)
					}
				}
			}
			if err == nil {
				fmt.Printf("%s: %d entries\n", args[1], l.Len())
			}
		case "tracker":
			var g []pkgaudit.Group
			if g, err = pkgaudit.LoadTracker(args[1]); err == nil && len(g) < 100 {
				err = errors.New("fewer than 100 entries: not the full tracker")
			}
			if err == nil {
				fmt.Printf("%s: %d advisory groups\n", args[1], len(g))
			}
		default:
			err = errors.New("give list or tracker")
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", args[1], err)
		return 1
	}
	return 0
}
