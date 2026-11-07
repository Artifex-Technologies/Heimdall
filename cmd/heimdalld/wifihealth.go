package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Artifex-Technologies/Heimdall/internal/wifihealth"
)

// cmdWifiHealth measures the Wi-Fi connection and says what is slowing it down (any user; Settings runs it with --json).
func cmdWifiHealth(args []string) int {
	fs := flag.NewFlagSet("wifi-health", flag.ContinueOnError)
	speed := fs.Bool("speed", false, "also run a speed test (Cloudflare's public speed test; up to a few hundred MB)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	iface := fs.String("iface", "", "Wi-Fi interface (default: the one carrying the default route)")
	api := fs.String("api", "127.0.0.1:8930", "Heimdall's API, for the number of devices on the network (empty: skip)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r, err := wifihealth.Run(wifihealth.Options{Iface: *iface, Speed: *speed, API: *api})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wifi-health:", err)
		return 1
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return 0
	}
	fmt.Println(r.Summary)
	if r.Connected {
		fmt.Printf("%s, %s channel %d (%d MHz), %d dBm, %.0f/%.0f Mbps\n", r.Link.SSID, r.Link.Band, r.Link.Channel, r.Link.Width, r.Link.SignalDBm, r.Link.RxMbps, r.Link.TxMbps)
	}
	mark := map[string]string{"good": "ok  ", "info": "    ", "warn": "WARN", "bad": "BAD "}
	for _, f := range r.Findings {
		fmt.Printf("  %s %s", mark[f.Status], f.Title)
		if f.Detail != "" {
			fmt.Printf(": %s", f.Detail)
		}
		fmt.Println()
	}
	return 0
}
