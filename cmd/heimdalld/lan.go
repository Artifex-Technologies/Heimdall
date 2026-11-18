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

// cmdLAN runs one scan of the current network (heimdall-lan-scan.service), prints the list, or records what the owner says
// a device is (kind MAC KIND, as root: Settings runs it through pkexec).
func cmdLAN(args []string) int {
	if len(args) == 0 || (args[0] != "scan" && args[0] != "list" && args[0] != "kind") {
		fmt.Fprintln(os.Stderr, "usage: heimdalld lan scan|list|kind [--dir DIR] [MAC KIND|guess]")
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
		case "not_home":
			fmt.Println("this network is trusted, but not as your home network: no scan (heimdall-wifi-guard trust --home turns the device list on)")
		case "router_changed":
			fmt.Println("the router is not the one recorded when this network was trusted: no scan")
		default:
			fmt.Println(r.Status)
		}
		return 0
	}
	if args[0] == "kind" {
		if fs.NArg() != 2 {
			fmt.Fprintln(os.Stderr, "usage: heimdalld lan kind [--dir DIR] MAC KIND|guess")
			return 2
		}
		m, err := lan.SetKind(*dir+"/"+lan.KindsFile, fs.Arg(0), fs.Arg(1))
		if err != nil {
			fmt.Fprintln(os.Stderr, "lan kind:", err)
			return 1
		}
		if fs.Arg(1) == "guess" {
			fmt.Printf("%s: the list's guess\n", m)
		} else {
			fmt.Printf("%s: %s\n", m, fs.Arg(1))
		}
		return 0
	}
	st, err := lan.Load(*dir + "/devices.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	st.ApplyKinds(lan.LoadKinds(*dir + "/" + lan.KindsFile))
	for _, n := range st.Networks {
		fmt.Printf("%s: %d devices, last scan %s\n", n.SSID, len(n.Devices), n.LastScan.Local().Format(time.DateTime))
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  IP\tNAME\tMAKER\tKIND\tFIRST SEEN\tLAST SEEN")
		for _, d := range n.Devices {
			kind := d.Kind
			if d.OwnerKind != "" {
				kind = d.OwnerKind // the owner's word over the guess
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", d.IP, d.Name, d.Vendor, kind,
				d.FirstSeen.Local().Format("2006-01-02 15:04"), d.LastSeen.Local().Format("2006-01-02 15:04"))
		}
		tw.Flush()
	}
	return 0
}
