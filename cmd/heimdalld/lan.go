package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/lan"
)

// cmdLAN runs one scan of the current network (heimdall-lan-scan.service) or prints the list.
func cmdLAN(args []string) int {
	if len(args) == 0 || (args[0] != "scan" && args[0] != "list") {
		fmt.Fprintln(os.Stderr, "usage: heimdalld lan scan|list [--dir DIR]")
		return 2
	}
	fs := flag.NewFlagSet("lan "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", "/var/lib/heimdall/lan", "state directory")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if args[0] == "scan" {
		if err := os.MkdirAll(*dir, 0o750); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		r, err := lan.Scan(lan.Options{Dir: *dir, Log: log.Printf})
		if err != nil {
			fmt.Fprintln(os.Stderr, "lan scan:", err)
			return 1
		}
		switch r.Status {
		case "scanned":
			fmt.Printf("%d devices, %d new\n", r.Devices, len(r.New))
		case "not_trusted":
			fmt.Println("this network is not trusted: no scan (heimdall-wifi-guard trust, at home)")
		case "router_changed":
			fmt.Println("the router is not the one recorded when this network was trusted: no scan")
		default:
			fmt.Println(r.Status)
		}
		return 0
	}
	st, err := lan.Load(*dir + "/devices.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, n := range st.Networks {
		fmt.Printf("%s: %d devices, last scan %s\n", n.SSID, len(n.Devices), n.LastScan.Local().Format(time.DateTime))
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  IP\tNAME\tMAKER\tKIND\tFIRST SEEN\tLAST SEEN")
		for _, d := range n.Devices {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", d.IP, d.Name, d.Vendor, d.Kind,
				d.FirstSeen.Local().Format("2006-01-02 15:04"), d.LastSeen.Local().Format("2006-01-02 15:04"))
		}
		tw.Flush()
	}
	return 0
}
