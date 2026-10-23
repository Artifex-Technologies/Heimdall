// Command heimdalld is Heimdall's agent-behavior monitor: it watches
// a Sarina workspace's session files and raises alerts for prompt
// injection, leaked credentials, invisible-Unicode smuggling, permission
// escalation, and abnormal session-creation bursts. See ../../README.md
// and ../../docs/ARCHITECTURE.md for the full design and roadmap.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/api"
	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/engine"
	"github.com/Artifex-Technologies/Heimdall/internal/governance"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
	"github.com/Artifex-Technologies/Heimdall/internal/maintenance"
	"github.com/Artifex-Technologies/Heimdall/internal/pkgaudit"
	"github.com/Artifex-Technologies/Heimdall/internal/pkgverify"
	"github.com/Artifex-Technologies/Heimdall/internal/response"
	"github.com/Artifex-Technologies/Heimdall/internal/scan"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/agentsource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/fwsource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/hostsource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/limbosource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/netsource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/wifisource"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "scan-files":
		os.Exit(cmdScanFiles(os.Args[2:]))
	case "maintenance":
		os.Exit(cmdMaintenance(os.Args[2:]))
	case "origin":
		os.Exit(cmdOrigin(os.Args[2:]))
	case "intel-check":
		os.Exit(cmdIntelCheck(os.Args[2:]))
	case "ipdb-check":
		os.Exit(cmdIPDBCheck(os.Args[2:]))
	case "version":
		fmt.Println("heimdalld " + version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "heimdalld: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `heimdalld -- Heimdall agent-behavior monitor

Usage:
  heimdalld run  --config PATH      Run the monitoring daemon in the foreground.
  heimdalld scan --config PATH      Scan once, print findings, exit non-zero on any.
  heimdalld maintenance on --for 2h --reason "why" [--config PATH]
                                    Open a maintenance window (root; at most 4h): routine alerts become info while it is open.
  heimdalld maintenance off|status [--config PATH]
  heimdalld origin [--config PATH] IP...
                                    Where addresses belong (country, network), from the offline IP database.
  heimdalld ipdb-check FILE...      Check downloaded IP database files (heimdall-intel-update runs this before using one).
  heimdalld intel-check list|tracker FILE
                                    Check a downloaded threat list or security tracker file before it is used.
  heimdalld scan-files [--state FILE] [--exclude PATTERN]... [--max-mb N] PATH...
                                    Scan files for malware with ClamAV (must be installed). Prints one line per finding; exit 1 if
                                    anything was found, 2 if ClamAV is missing or a file could not be scanned. Runs as the calling
                                    user; with --state, unchanged files are skipped next time.
  heimdalld version                 Print the version and exit.

See README.md and docs/ARCHITECTURE.md for configuration and design.
`)
}

func loadConfigFlag(args []string) (config.Config, error) {
	fs := flag.NewFlagSet("heimdalld", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to a JSON config file (optional)")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	return config.Load(*configPath)
}

func newDetectors(cfg config.Config) []detect.Detector {
	return []detect.Detector{
		detect.NewInjectionDetector(),
		detect.NewCredentialDetector(),
		detect.NewUnicodeDetector(),
		detect.NewEscalationDetector(),
		detect.NewBurstDetector(cfg.BurstWindow(), cfg.BurstThreshold, cfg.BurstCooldown()),
		detect.NewPackageAwareFileIntegrityDetector(pkgverify.New(cfg.PacmanDB)),
		detect.NewMaintenanceDetector(),
		detect.NewResourcePressureDetector(cfg.ResourceMemThresholdPercent, cfg.ResourceLoadThresholdPerCPU),
		detect.NewNetworkExposureDetector(),
		detect.NewConnectionDetector(),
		detect.NewInboundDetector(),
		detect.NewPackageVulnerabilityDetector(),
		detect.NewWifiDetector(),
		detect.NewBaselineDriftDetectorWithFloors(cfg.BaselineMinSamples, cfg.BaselineZThreshold, detect.DefaultBaselineFloors),
		detect.NewLimboGuestDetector(),
	}
}

func cmdRun(args []string) int {
	cfg, err := loadConfigFlag(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld:", err)
		return 2
	}
	if cfg.AgentSessionDir == "" && cfg.LimboEventLog == "" {
		fmt.Fprintln(os.Stderr, "heimdalld: neither agent_session_dir nor limbo_event_log is set in config; nothing to watch")
		return 2
	}

	logger := log.New(os.Stderr, "heimdalld: ", log.LstdFlags)

	sinks := []alert.Sink{alert.NewWriterSink(os.Stdout)}
	ring := alert.NewRing(cfg.RingSize)
	sinks = append(sinks, ring)
	if cfg.AlertLogPath != "" {
		f, err := os.OpenFile(cfg.AlertLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			logger.Printf("could not open alert_log_path %s: %v (continuing without it)", cfg.AlertLogPath, err)
		} else {
			defer f.Close()
			sinks = append(sinks, alert.NewWriterSink(f))
		}
	}

	multiSink := alert.NewMultiSink(sinks...)
	var engineSink alert.Sink = multiSink
	var resp *response.Responder
	if cfg.LimboControlSocket != "" && cfg.LimboAutoQuarantine {
		resp = &response.Responder{Next: multiSink, Limbo: response.NewClient(cfg.LimboControlSocket), Log: logger,
			DelayThreshold: time.Duration(cfg.LimboQuarantineDelaySeconds) * time.Second, BacklogThreshold: cfg.LimboBacklogThreshold}
		if cfg.SarinaURL != "" {
			token := cfg.SarinaToken
			if token == "" {
				token = os.Getenv("HEIMDALL_SARINA_TOKEN")
			}
			adv, err := response.NewSarina(cfg.SarinaURL, token, cfg.SarinaCwd)
			if err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld:", err)
				return 2
			}
			resp.Advisor = adv
		}
		engineSink = resp
		logger.Printf("Limbo quarantine response enabled (control socket %s, Sarina advisories: %v)", cfg.LimboControlSocket, cfg.SarinaURL != "")
	}
	eng := engine.New(engineSink, logger, newDetectors(cfg)...)
	win := maintenance.NewWatcher(cfg.MaintenancePath)
	eng.SetMaintenance(win, cfg.MaintenanceSoften)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go watchMaintenance(ctx, cfg.MaintenancePath, eng.Handle)

	if cfg.APIAddr != "" {
		reviewer := governance.NewReviewer(multiSink)
		srv := api.NewServer(ring, reviewer)
		go func() {
			logger.Printf("status API listening on %s", cfg.APIAddr)
			if err := api.ListenAndServeLoopback(cfg.APIAddr, srv); err != nil {
				logger.Printf("status API stopped: %v", err)
			}
		}()
	}

	telemetry := hostsource.NewTelemetryWatcher()
	go telemetry.Run(ctx, cfg.TelemetryInterval(),
		func(err error) { logger.Printf("host telemetry unavailable, disabling: %v", err) },
		func(err error) { logger.Printf("telemetry poll error: %v", err) },
		eng.Handle,
	)

	if len(cfg.FIMPaths) > 0 {
		logger.Printf("watching %d file(s) for integrity (poll every %s)", len(cfg.FIMPaths), cfg.FIMPollInterval())
		fim := hostsource.NewFIMWatcherWithState(cfg.FIMPaths, cfg.FIMStatePath)
		go fim.Run(ctx, cfg.FIMPollInterval(), func(err error) {
			logger.Printf("fim state save error: %v", err)
		}, eng.Handle)
	}

	if len(cfg.NetPorts) > 0 {
		logger.Printf("watching %d ecosystem port(s) for non-loopback exposure (poll every %s)", len(cfg.NetPorts), cfg.NetPollInterval())
		ports := netsource.NewPortWatcher(cfg.NetPorts)
		go ports.Run(ctx, cfg.NetPollInterval(),
			func(err error) { logger.Printf("network exposure watch unavailable, disabling: %v", err) },
			func(err error) { logger.Printf("network exposure poll error: %v", err) },
			eng.Handle,
		)
	}

	origins := ipintel.NewResolver(cfg.IPDatabases...)
	if origins.Available() {
		logger.Printf("naming where remote addresses belong from the offline IP database")
	} else {
		logger.Printf("no IP database yet: remote addresses show no origin (heimdall-intel-update fetches one)")
	}

	threats := ipintel.NewLists(cfg.ThreatListDir)
	if n, e := threats.Count(); n > 0 {
		logger.Printf("checking connections against %d threat list(s), %d entries", n, e)
	} else {
		logger.Printf("no threat lists yet (heimdall-intel-update fetches them)")
	}
	if cfg.SecurityTracker != "" {
		pw := &pkgaudit.Watcher{TrackerPath: cfg.SecurityTracker, PacmanDB: cfg.PacmanDB, StatePath: cfg.PackageAuditStatePath}
		every := time.Duration(max(cfg.PackageAuditIntervalHours, 1)) * time.Hour
		logger.Printf("matching installed packages against the security tracker (every %s)", every)
		go pw.Run(ctx, every, func(err error) { logger.Printf("package audit: %v", err) }, eng.Handle)
	}

	if cfg.ConnWatch {
		logger.Printf("logging connections per process (poll every %s)", cfg.ConnPollInterval())
		cw := netsource.NewConnWatcher(cfg.ConnStatePath, cfg.AppNetworkPolicy)
		cw.Origins = origins
		cw.Threats = threats
		go cw.Run(ctx, cfg.ConnPollInterval(),
			func(err error) { logger.Printf("connection watch unavailable, disabling: %v", err) },
			func(err error) { logger.Printf("connection watch error: %v", err) },
			eng.Handle,
		)
	}

	if cfg.WifiResults != "" {
		ww := &wifisource.Watcher{Path: cfg.WifiResults, OffsetPath: cfg.WifiResults + ".offset"}
		go ww.Run(ctx, 10*time.Second, func(err error) { logger.Printf("wifi results: %v", err) }, eng.Handle)
	}

	if cfg.Firewall {
		logger.Printf("watching the firewall and SSH logins in the journal (poll every %s)", cfg.FirewallPollInterval())
		fw := fwsource.NewWatcher(cfg.FirewallCursorPath, origins)
		fw.Threats = threats
		go fw.Run(ctx, cfg.FirewallPollInterval(),
			func(err error) { logger.Printf("firewall watch unavailable, disabling: %v", err) },
			func(err error) { logger.Printf("firewall watch error: %v", err) },
			eng.Handle,
		)
	}

	if cfg.LimboEventLog != "" {
		logger.Printf("watching Limbo event log %s (poll every %s)", cfg.LimboEventLog, cfg.LimboPollInterval())
		lw := limbosource.NewWatcher(cfg.LimboEventLog, cfg.LimboStatePath, false)
		go lw.Run(ctx, cfg.LimboPollInterval(),
			func(err error) { logger.Printf("limbo event log poll error: %v", err) },
			func(e detect.Event) {
				eng.Handle(e)
				if resp != nil {
					resp.Observe(e) // after the engine, so a trigger is ordered before what follows it
				}
			},
		)
	}

	if cfg.AgentSessionDir == "" {
		<-ctx.Done() // the other sources run in goroutines; keep the process alive
	} else {
		logger.Printf("watching %s (poll every %s)", cfg.AgentSessionDir, cfg.PollInterval())
		watcher := agentsource.NewWatcher(cfg.AgentSessionDir)
		watcher.Run(ctx, cfg.PollInterval(), func(err error) {
			logger.Printf("poll error: %v", err)
			var issue agentsource.Issue
			if errors.As(err, &issue) { // also put it in the alert stream, with its code and remedy
				multiSink.Write(alert.Integration(issue.Code, issue.Path+": "+issue.Detail, issue.Remedy, map[string]string{"path": issue.Path}))
			}
		}, eng.Handle)
	}

	logger.Println("shutting down")
	if resp != nil && !resp.Shutdown(3*time.Second) {
		logger.Println("abandoned in-flight Limbo quarantine or advisory calls")
	}
	return 0
}

func cmdScan(args []string) int {
	cfg, err := loadConfigFlag(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld:", err)
		return 2
	}
	if cfg.AgentSessionDir == "" && cfg.LimboEventLog == "" {
		fmt.Fprintln(os.Stderr, "heimdalld: neither agent_session_dir nor limbo_event_log is set in config; nothing to scan")
		return 2
	}

	logger := log.New(os.Stderr, "heimdalld: ", log.LstdFlags)
	ring := alert.NewRing(cfg.RingSize)
	eng := engine.New(ring, logger, newDetectors(cfg)...)
	scanIncomplete := false // some session file could not be read

	if cfg.AgentSessionDir != "" {
		watcher := agentsource.NewWatcher(cfg.AgentSessionDir)
		events, err := watcher.Poll()
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld:", err)
			return 2
		}
		for _, e := range events {
			eng.Handle(e)
		}
		// A file that could not be read was not audited; that must not read as clean.
		for _, i := range watcher.Issues() {
			fmt.Fprintln(os.Stderr, "heimdalld: warning:", i)
			scanIncomplete = true
		}
	}

	// A scan is an audit, so it reads Limbo's whole log and keeps no offset.
	if cfg.LimboEventLog != "" {
		// Poll treats a missing log as normal (Limbo may not have run yet), but
		// in an audit a configured-yet-absent file must not read as a clean
		// result -- usually it means a wrong path.
		if _, statErr := os.Stat(cfg.LimboEventLog); os.IsNotExist(statErr) {
			fmt.Fprintf(os.Stderr, "heimdalld: warning: limbo_event_log %s does not exist; nothing audited there\n", cfg.LimboEventLog)
		}
		lw := limbosource.NewWatcher(cfg.LimboEventLog, "", true)
		limboEvents, err := lw.Poll()
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld: limbo event log:", err)
			return 2
		}
		for _, e := range limboEvents {
			eng.Handle(e)
		}
		if lw.Skipped > 0 {
			fmt.Fprintf(os.Stderr, "heimdalld: %d unparseable line(s) in the Limbo event log\n", lw.Skipped)
		}
	}

	if len(cfg.FIMPaths) > 0 {
		fim := hostsource.NewFIMWatcherWithState(cfg.FIMPaths, cfg.FIMStatePath)
		fimEvents, err := fim.Poll()
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld: fim state save error:", err)
		}
		for _, e := range fimEvents {
			eng.Handle(e)
		}
	}

	// Telemetry and network-exposure checks are best-effort in a one-shot
	// scan: missing /proc (any non-Linux platform) is expected and silent,
	// anything else is worth printing but not worth failing the scan over.
	telemetry := hostsource.NewTelemetryWatcher()
	if ev, err := telemetry.Poll(); err == nil {
		eng.Handle(ev)
	} else if !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "heimdalld: telemetry poll error:", err)
	}

	if len(cfg.NetPorts) > 0 {
		ports := netsource.NewPortWatcher(cfg.NetPorts)
		if netEvents, err := ports.Poll(); err == nil {
			for _, e := range netEvents {
				eng.Handle(e)
			}
		} else if !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "heimdalld: network exposure poll error:", err)
		}
	}

	found := ring.Recent(0)
	if len(found) == 0 {
		fmt.Println("heimdalld: no findings")
		if scanIncomplete {
			return 2 // not a clean bill of health: see the warnings above
		}
		return 0
	}
	sink := alert.NewWriterSink(os.Stdout)
	worst := detect.SeverityInfo
	for i := len(found) - 1; i >= 0; i-- { // oldest first
		_ = sink.Write(found[i])
		if found[i].Severity == detect.SeverityCritical {
			worst = detect.SeverityCritical
		} else if found[i].Severity == detect.SeverityWarning && worst != detect.SeverityCritical {
			worst = detect.SeverityWarning
		}
	}
	if worst == detect.SeverityInfo {
		if scanIncomplete {
			return 2
		}
		return 0
	}
	return 1
}

// watchMaintenance emits an event when a maintenance window opens or closes, so the owner sees it in the alert log.
func watchMaintenance(ctx context.Context, path string, emit func(detect.Event)) {
	var prev maintenance.Window
	open := false
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		w, found := maintenance.Read(path)
		now := time.Now()
		active := found && w.Active(now)
		if active && (!open || w.Opened != prev.Opened) {
			emit(detect.Event{Source: "maintenance", Time: now, Kind: "maintenance_opened", Text: w.Reason,
				Fields: map[string]string{"actor": w.Actor, "reason": w.Reason, "until": w.Until.Format("15:04")}})
			prev, open = w, true
		} else if !active && open {
			emit(detect.Event{Source: "maintenance", Time: now, Kind: "maintenance_closed", Text: prev.Reason,
				Fields: map[string]string{"actor": prev.Actor, "reason": prev.Reason}})
			open = false
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func cmdMaintenance(args []string) int {
	if len(args) == 0 || (args[0] != "on" && args[0] != "off" && args[0] != "status") {
		fmt.Fprintln(os.Stderr, `usage: heimdalld maintenance on --for 2h --reason "why" | off | status   [--config PATH]`)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("maintenance", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/heimdall/config.json", "config file")
	dur := fs.Duration("for", 0, "how long (at most 4h)")
	reason := fs.String("reason", "", "why (required for on)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld:", err)
		return 2
	}
	now := time.Now()
	if action == "status" {
		w, found := maintenance.Read(cfg.MaintenancePath)
		fmt.Println(maintenance.Describe(w, found, now))
		return 0
	}
	// who is asking: the user behind sudo, else the current user
	actor := os.Getenv("SUDO_USER")
	if actor == "" {
		actor = os.Getenv("USER")
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "heimdalld: only root can change the maintenance window (use sudo)")
		return 1
	}
	if len(cfg.MaintenanceActors) > 0 {
		ok := false
		for _, a := range cfg.MaintenanceActors {
			ok = ok || a == actor
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "heimdalld: %q is not in maintenance_actors\n", actor)
			return 1
		}
	}
	if action == "off" {
		if err := maintenance.Clear(cfg.MaintenancePath); err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld:", err)
			return 1
		}
		fmt.Println("maintenance window closed")
		return 0
	}
	w, err := maintenance.Open(actor, *reason, *dur, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld:", err)
		return 2
	}
	if err := maintenance.Write(cfg.MaintenancePath, w); err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld:", err)
		return 1
	}
	fmt.Println(maintenance.Describe(w, true, now))
	return 0
}

type listFlag []string

func (l *listFlag) String() string     { return fmt.Sprint(*l) }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdScanFiles(args []string) int {
	fs := flag.NewFlagSet("scan-files", flag.ContinueOnError)
	statePath := fs.String("state", "", "remember scanned files here (skips unchanged ones next time)")
	maxMB := fs.Int64("max-mb", 200, "skip files larger than this many MB (0 = no limit)")
	var exclude listFlag
	fs.Var(&exclude, "exclude", "a folder, file or glob that is never scanned (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "heimdalld scan-files: give at least one file or folder")
		return 2
	}
	sc := scan.NewClamAV()
	if !sc.Available() {
		fmt.Fprintln(os.Stderr, "heimdalld scan-files: ClamAV is not installed (pacman -S clamav); nothing was scanned")
		return 2
	}
	start := time.Now()
	st := scan.LoadState(*statePath)
	files, err := scan.Collect(fs.Args(), scan.Options{Exclude: scan.Excluder{Patterns: exclude}, MaxBytes: *maxMB << 20, State: st})
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld scan-files:", err)
		return 2
	}
	found, failed := 0, 0
	for _, r := range scan.Run(context.Background(), sc, files, st) {
		switch {
		case r.Infected:
			found++
			fmt.Printf("INFECTED %s: %s\n", r.Path, r.Signature)
		case r.Error != "":
			failed++
			fmt.Fprintf(os.Stderr, "could not scan %s: %s\n", r.Path, r.Error)
		}
	}
	_ = st.Save()
	fmt.Printf("scanned %d files in %s: %d infected, %d could not be scanned\n", len(files), scan.Elapsed(start), found, failed)
	switch {
	case found > 0:
		return 1
	case failed > 0:
		return 2
	}
	return 0
}
