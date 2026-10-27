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
	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
	"github.com/Artifex-Technologies/Heimdall/internal/safefs"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/rasource"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/api"
	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/contain"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/engine"
	"github.com/Artifex-Technologies/Heimdall/internal/governance"
	"github.com/Artifex-Technologies/Heimdall/internal/hardening"
	"github.com/Artifex-Technologies/Heimdall/internal/immunity"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
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
	"github.com/Artifex-Technologies/Heimdall/internal/trust"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "remote": // the remote-access tools Heimdall knows, and the owner's approvals (docs/REMOTE_ACCESS.md)
		os.Exit(runRemote(os.Args[2:]))
	case safefs.ChildCommand: // a write already running as the file's owner (internal/safefs)
		if err := safefs.Child(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "scan-files":
		os.Exit(cmdScanFiles(os.Args[2:]))
	case "maintenance":
		os.Exit(cmdMaintenance(os.Args[2:]))
	case "trust":
		os.Exit(cmdTrust(os.Args[2:]))
	case "immunity":
		os.Exit(cmdImmunity(os.Args[2:]))
	case "kernel-check":
		os.Exit(cmdKernelCheck(os.Args[2:]))
	case "contain":
		os.Exit(cmdContain(os.Args[2:]))
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
  heimdalld intel-check list|tracker FILE | kernel ARCHIVE OUT [EXPLOITED]
                                    Check a downloaded threat list or security tracker file before it is used.
  heimdalld scan-files [--state FILE] [--exclude PATTERN]... [--max-mb N] PATH...
                                    Scan files for malware with ClamAV (must be installed). Prints one line per finding; exit 1 if
                                    anything was found, 2 if ClamAV is missing or a file could not be scanned. Runs as the calling
                                    user; with --state, unchanged files are skipped next time.
  heimdalld trust init|status|mode|sign|forget|restore|verify|watch ...
                                    The signed list of files that decide how the AI agents behave (heimdalld trust for details).
  heimdalld immunity add|suspect|confirm|list|forget|check ...
                                    Malware learned beyond ClamAV: fingerprints ClamAV loads, so every scan catches copies.
  heimdalld kernel-check [--all]   Known holes in each installed kernel that a newer kernel fixes (offline, from the kernel's CVE list).
  heimdalld contain status|now|emergency|release
                                    Stop a compromised AI agent: unload the models, stop and lock Sarina; the last resort clears
                                    the graphics card and restarts (heimdalld contain for details).
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

// remoteApprovals is the owner's list of approved remote-access tools (heimdalld remote approve).
var remoteApprovals = &remoteaccess.Approvals{Path: "/etc/heimdall/remote-access-approved.json"}

func newDetectors(cfg config.Config) []detect.Detector {
	return []detect.Detector{
		detect.NewInjectionDetector(),
		detect.NewCredentialDetector(),
		detect.NewUnicodeDetector(),
		detect.NewEscalationDetector(),
		detect.NewBurstDetector(cfg.BurstWindow(), cfg.BurstThreshold, cfg.BurstCooldown()),
		detect.NewPackageAwareFileIntegrityDetector(pkgverify.New(cfg.PacmanDB)).WithTrust(trust.Judge{Store: trust.Store{Dir: trust.DefaultDir}}),
		detect.NewMaintenanceDetector(),
		detect.NewResourcePressureDetector(cfg.ResourceMemThresholdPercent, cfg.ResourceLoadThresholdPerCPU),
		detect.NewNetworkExposureDetector(),
		detect.NewConnectionDetector(),
		detect.NewInboundDetector(),
		detect.NewPackageVulnerabilityDetector(),
		detect.NewKernelVulnerabilityDetector(),
		detect.NewHardeningDetector(),
		detect.NewWifiDetector(),
		detect.NewLANDetector(),
		detect.NewBaselineDriftDetectorWithFloors(cfg.BaselineMinSamples, cfg.BaselineZThreshold, detect.DefaultBaselineFloors),
		detect.NewLimboGuestDetector(),
		detect.NewRemoteAccessDetector(remoteApprovals.Approved),
	}
}

func cmdRun(args []string) int {
	cfg, err := loadConfigFlag(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld:", err)
		return 2
	}
	// Heimdall watches the computer itself (files, network, packages, the firewall) with or without an AI agent or Limbo: those
	// two are extra sources, not a reason to refuse to start.
	logger := log.New(os.Stderr, "heimdalld: ", log.LstdFlags)
	if cfg.AgentSessionDir == "" && cfg.LimboEventLog == "" {
		logger.Printf("no AI agent sessions or Limbo log to watch; watching the computer itself")
	}
	if !sarinaInstalled(cfg) {
		logger.Printf("Sarina is not installed: running on my own (alerts are explained with built-in text)")
	}

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
			resp.Advisor = response.IfInstalled{Inner: adv, Installed: func() bool { return sarinaInstalled(cfg) }}
		}
		engineSink = resp
		logger.Printf("Limbo quarantine response enabled (control socket %s, Sarina advisories: %v)", cfg.LimboControlSocket, cfg.SarinaURL != "")
	}
	// a critical finding about the AI agents asks the root unit to contain them (only when switched on in contain.json)
	engineSink = &contain.Trigger{Next: engineSink, ConfigPath: contain.ConfigPath, RequestPath: contain.RequestPath, MarkerPath: contain.MarkerPath}
	eng := engine.New(engineSink, logger, newDetectors(cfg)...)
	win := maintenance.NewWatcher(cfg.MaintenancePath)
	eng.SetMaintenance(win, cfg.MaintenanceSoften)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go watchMaintenance(ctx, cfg.MaintenancePath, eng.Handle)

	if cfg.APIAddr != "" {
		reviewer := governance.NewReviewer(multiSink)
		srv := api.NewServer(ring, reviewer)
		srv.SetAudit(func() any { return audit(cfg) })
		srv.SetQuarantine(func() any {
			es, err := immunity.Default().Load()
			if err != nil || es == nil {
				return []immunity.Entry{}
			}
			return es
		})
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

	// with trust on, the AI agents' behaviour files and folders are watched too (their changes judged against the signed list after a
	// short grace, so a change signed right after it was made stays quiet)
	ts := trust.Store{Dir: trust.DefaultDir}
	tw := trust.WatchList{}
	if ts.Mode() != trust.Off {
		tw = ts.Watch()
		logger.Printf("trust %s: watching %d behaviour file(s) and %d folder(s) of the AI agents", ts.Mode(), len(tw.Files), len(tw.Dirs))
	}
	if len(cfg.FIMPaths) > 0 || len(tw.Files)+len(tw.Dirs) > 0 {
		logger.Printf("watching %d file(s) for integrity (poll every %s)", len(cfg.FIMPaths), cfg.FIMPollInterval())
		fim := hostsource.NewFIMWatcherWithState(cfg.FIMPaths, cfg.FIMStatePath).WithTrust(tw.Files, tw.Dirs, 2*time.Minute)
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

	if cfg.KernelVulns != "" {
		kw := &kernelaudit.Watcher{ListPath: cfg.KernelVulns, ModulesDir: "/usr/lib/modules", StatePath: cfg.KernelAuditStatePath}
		every := time.Duration(max(cfg.PackageAuditIntervalHours, 1)) * time.Hour
		go kw.Run(ctx, every, func(err error) { logger.Printf("kernel audit: %v", err) }, eng.Handle)
	}

	if cfg.HardeningStatePath != "" {
		hw := &hardening.Watcher{StatePath: cfg.HardeningStatePath}
		go hw.Run(ctx, time.Duration(max(cfg.PackageAuditIntervalHours, 1))*time.Hour, eng.Handle)
	}

	if cfg.ConnWatch {
		logger.Printf("logging connections per process (poll every %s)", cfg.ConnPollInterval())
		cw := netsource.NewConnWatcher(cfg.ConnStatePath, cfg.AppNetworkPolicy)
		cw.RemoteAccess = &remoteaccess.Identifier{Catalog: remoteaccess.Builtin()}
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
		// while on an untrusted Wi-Fi network, its router is watched for impersonation (reads the kernel's tables only)
		rw := netsource.NewRouterWatcher(filepath.Join(filepath.Dir(cfg.WifiResults), "current.json"))
		go rw.Run(ctx, 10*time.Second, eng.Handle)
	}
	if cfg.ListenWatch {
		go netsource.NewListenWatcher().Run(ctx, 15*time.Second, eng.Handle)
		// remote-access tools by what is installed and which tunnel interfaces exist (docs/REMOTE_ACCESS.md)
		ra := remoteaccess.Builtin()
		go rasource.New(ra).Run(ctx, 15*time.Second, eng.Handle)
		log.Printf("watching for %d remote-access tools (installed packages and tunnel interfaces every 15s, connections by program)", len(ra.Providers))
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
		if cfg.AgentStatePath != "" {
			watcher = agentsource.NewWatcherWithState(cfg.AgentSessionDir, cfg.AgentStatePath)
		}
		watcher.Run(ctx, cfg.PollInterval(), func(err error) {
			var issue agentsource.Issue
			// no session folder because Sarina is not installed: nothing is wrong, there is just nothing to read yet
			if errors.As(err, &issue) && issue.Code == agentsource.CodeUnreadable && !sarinaInstalled(cfg) {
				if _, statErr := os.Stat(cfg.AgentSessionDir); os.IsNotExist(statErr) {
					return
				}
			}
			logger.Printf("poll error: %v", err)
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
	st.UseSignatures(scan.FileStamp(immunity.DefaultSignatures))
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

// sarinaInstalled says whether Sarina is on this computer (her program exists). Without the setting, she is taken to be there, as
// before this setting existed.
func sarinaInstalled(cfg config.Config) bool {
	if cfg.SarinaInstalled == "" {
		return true
	}
	_, err := os.Stat(cfg.SarinaInstalled)
	return err == nil
}

func runRemote(args []string) int {
	c := remoteaccess.Builtin()
	if len(args) == 0 || args[0] == "list" {
		for _, p := range c.Providers {
			mark := " "
			if remoteApprovals.Approved(p.ID) {
				mark = "*"
			}
			fmt.Printf("%s %-14s %-15s %s\n", mark, p.ID, p.Kind, p.Name)
		}
		fmt.Println("(* approved: Heimdall reports it as info instead of critical)")
		return 0
	}
	if len(args) != 2 || (args[0] != "approve" && args[0] != "forget") {
		fmt.Fprintln(os.Stderr, "usage: heimdalld remote list | approve ID | forget ID")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "heimdalld remote: approving needs root (sudo)")
		return 1
	}
	var p *remoteaccess.Provider
	for i := range c.Providers {
		if c.Providers[i].ID == args[1] {
			p = &c.Providers[i]
		}
	}
	if p == nil {
		fmt.Fprintln(os.Stderr, "heimdalld remote: no such tool (heimdalld remote list)")
		return 2
	}
	if args[0] == "approve" && !p.Approvable() {
		fmt.Fprintf(os.Stderr, "heimdalld remote: %s is a command-and-control implant and can never be approved\n", p.Name)
		return 2
	}
	ids, err := remoteaccess.SetApproved(remoteApprovals.Path, p.ID, args[0] == "approve")
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld remote:", err)
		return 1
	}
	fmt.Println("approved:", strings.Join(ids, ", "))
	return 0
}
