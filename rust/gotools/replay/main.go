// Command replay runs event lines through the Go daemon's detectors and engine and writes the alert lines, as
// `heimdalld-rs replay` does for the Rust port, so the two can be fed the same events and their alerts compared
// (rust/parity/engine-differential.sh). Event line format: internal/parity EventJSON.
//
//	go run ./rust/gotools/replay --config CONFIG [--approvals FILE] < events.jsonl > alerts.jsonl
//
// The system is left out as in the Rust replay: no package database, no trust list, the temporary port range 32768-60999;
// the mesh peers, maintenance window and remote approvals come from the config's paths and --approvals.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/engine"
	"github.com/Artifex-Technologies/Heimdall/internal/maintenance"
	"github.com/Artifex-Technologies/Heimdall/internal/mesh"
	"github.com/Artifex-Technologies/Heimdall/internal/parity"
	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
)

func main() {
	configPath := flag.String("config", "", "the daemon's config file")
	approvals := flag.String("approvals", "/etc/heimdall/remote-access-approved.json", "the remote-access approvals file")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replay:", err)
		os.Exit(2)
	}
	appr := &remoteaccess.Approvals{Path: *approvals}
	deps := parity.Deps{
		MeshPeerFunc: func(ip string) (string, bool) { return mesh.IsPeerHost(cfg.MeshPeersPath, ip) },
		ApprovedFunc: appr.Approved,
	}
	out := bufio.NewWriterSize(os.Stdout, 1<<16)
	defer out.Flush()
	eng := engine.New(alert.NewWriterSink(out), nil, parity.Detectors(cfg, deps)...)
	eng.SetMaintenance(maintenance.NewWatcher(cfg.MaintenancePath), cfg.MaintenanceSoften)
	in := bufio.NewReaderSize(os.Stdin, 1<<16)
	for n := 1; ; n++ {
		line, err := in.ReadBytes('\n')
		if len(line) > 0 && string(line) != "\n" {
			var e parity.EventJSON
			if jerr := json.Unmarshal(line, &e); jerr != nil {
				fmt.Fprintf(os.Stderr, "replay: event line %d: %v\n", n, jerr)
				os.Exit(2)
			}
			ev, terr := e.Event()
			if terr != nil {
				fmt.Fprintf(os.Stderr, "replay: event line %d: %v\n", n, terr)
				os.Exit(2)
			}
			eng.Handle(ev)
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			os.Exit(2)
		}
	}
}
