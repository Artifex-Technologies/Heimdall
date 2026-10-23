package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
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
	if !r.Available() {
		fmt.Fprintln(os.Stderr, "heimdalld: no IP database yet (run heimdall-ipdb-update); only private and reserved addresses can be named")
	}
	rc := 0
	for _, a := range fs.Args() {
		ip := net.ParseIP(a)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "%s: not an IP address\n", a)
			rc = 1
			continue
		}
		fmt.Printf("%s  %s\n", ip, r.Lookup(ip))
	}
	return rc
}

// cmdIPDBCheck opens database files and says what they are; exit 1 if one is not a usable database. heimdall-ipdb-update
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
