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
	"github.com/Artifex-Technologies/Heimdall/internal/response"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/agentsource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/hostsource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/limbosource"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/netsource"
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
		detect.NewFileIntegrityDetector(),
		detect.NewResourcePressureDetector(cfg.ResourceMemThresholdPercent, cfg.ResourceLoadThresholdPerCPU),
		detect.NewNetworkExposureDetector(),
		detect.NewBaselineDriftDetector(cfg.BaselineMinSamples, cfg.BaselineZThreshold),
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
				token = os.Getenv("SENTRY_SARINA_TOKEN")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
