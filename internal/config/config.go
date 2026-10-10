// Package config loads heimdalld's configuration: a JSON file with every
// field optional, layered over defaults sized for a single-operator
// workstation rather than a fleet.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	// AgentSessionDir is the Sarina workspace's .port_sessions directory
	// this instance of Heimdall watches. Required to do anything useful;
	// left empty by default because the sensible value is a sibling
	// repo's path on this machine, not something to guess.
	AgentSessionDir string `json:"agent_session_dir"`

	// PollIntervalSeconds is how often the agent source rescans
	// AgentSessionDir.
	PollIntervalSeconds int `json:"poll_interval_seconds"`

	// AlertLogPath, if set, appends one JSON object per line per alert.
	// Empty means stdout only.
	AlertLogPath string `json:"alert_log_path"`

	// RingSize bounds how many recent alerts the status API keeps in
	// memory.
	RingSize int `json:"ring_size"`

	// APIAddr is the loopback address:port the status API binds, per the
	// ecosystem's loopback-only convention. Empty disables the API.
	APIAddr string `json:"api_addr"`

	// Burst detector tuning -- see detect.NewBurstDetector.
	BurstWindowSeconds   int `json:"burst_window_seconds"`
	BurstThreshold       int `json:"burst_threshold"`
	BurstCooldownSeconds int `json:"burst_cooldown_seconds"`

	// FIMPaths is the fixed, explicit list of files Phase 2's file-
	// integrity watcher polls. Empty (the default) disables it entirely --
	// like AgentSessionDir, there is no sensible default path to guess.
	FIMPaths               []string `json:"fim_paths"`
	FIMPollIntervalSeconds int      `json:"fim_poll_interval_seconds"`

	// FIMStatePath persists file-integrity baselines to disk so they
	// survive a heimdalld restart or a one-shot `scan` invocation (each is a
	// fresh process with an empty in-memory map otherwise). Empty disables
	// persistence -- every run/scan then re-establishes a fresh baseline
	// silently, which defeats FIM's purpose outside a single long-lived
	// `run` process, so packaging/arch/config.json.example always sets it.
	FIMStatePath string `json:"fim_state_path"`

	// Host telemetry (memory + load) tuning. Telemetry itself cannot be
	// disabled independently -- it's cheap enough (two /proc reads) to
	// always run on a supported platform, and self-disables gracefully
	// where /proc doesn't exist (see hostsource.TelemetryWatcher.Run).
	TelemetryIntervalSeconds    int     `json:"telemetry_interval_seconds"`
	ResourceMemThresholdPercent float64 `json:"resource_mem_threshold_percent"`
	ResourceLoadThresholdPerCPU float64 `json:"resource_load_threshold_per_cpu"`

	// NetPorts is the ecosystem's own port registry (Sarina's
	// docs/ECOSYSTEM.md §6, extended by this repo with 8930) -- unlike
	// AgentSessionDir/FIMPaths these are fixed constants shared by every
	// Chymaera OS install, not a per-machine path, so they default on
	// rather than requiring opt-in. Self-disables gracefully where /proc
	// doesn't exist, same as telemetry.
	NetPorts               []int `json:"net_ports"`
	NetPollIntervalSeconds int   `json:"net_poll_interval_seconds"`

	// LimboEventLog is the path to Limbo's events.jsonl (Limbo's
	// docs/EVENTS.md). Empty disables the source -- like AgentSessionDir
	// there is no default to guess, since it depends on which user runs
	// limbo. LimboStatePath, if set, persists the read offset so a restart
	// resumes instead of skipping to the end (see limbosource).
	LimboEventLog            string `json:"limbo_event_log"`
	LimboStatePath           string `json:"limbo_state_path"`
	LimboPollIntervalSeconds int    `json:"limbo_poll_interval_seconds"`

	// LimboControlSocket is Limbo's control.sock. When set, `run` responds to a
	// Limbo guest found unsafe by asking Limbo to restrict it (cut its
	// network). That socket can restrict and annotate only; it has no route to
	// release a guest or give a verdict, which stay with a human. Empty
	// disables the response entirely (alerts are still raised).
	LimboControlSocket string `json:"limbo_control_socket"`
	// LimboAutoQuarantine turns the response off without removing the socket.
	LimboAutoQuarantine bool `json:"limbo_auto_quarantine"`
	// LimboQuarantineDelaySeconds is how long a queued quarantine request may wait
	// before limbo_quarantine_delayed is raised; LimboBacklogThreshold is how many
	// waiting requests raise the backlog alert. Zero keeps the defaults (15 s, 4).
	LimboQuarantineDelaySeconds int `json:"limbo_quarantine_delay_seconds"`
	LimboBacklogThreshold       int `json:"limbo_backlog_threshold"`

	// SarinaURL, when set with a quarantine response, asks the local Sarina
	// service for an advisory opinion on each new quarantine. Must be a
	// loopback URL. The token may instead come from HEIMDALL_SARINA_TOKEN so it
	// need not sit in this file. SarinaCwd is a directory that exists for
	// Sarina's session API; nothing is read from it.
	SarinaURL   string `json:"sarina_url"`
	SarinaToken string `json:"sarina_token"`
	SarinaCwd   string `json:"sarina_cwd"`

	// Baseline-drift detector tuning (Phase 5) -- see
	// detect.NewBaselineDriftDetector. Runs by default on the same
	// host_telemetry Events the resource-pressure detector already
	// consumes; no separate source or opt-in needed.
	BaselineMinSamples int     `json:"baseline_min_samples"`
	BaselineZThreshold float64 `json:"baseline_z_threshold"`
}

func Default() Config {
	return Config{
		PollIntervalSeconds:  5,
		RingSize:             500,
		APIAddr:              "127.0.0.1:8930",
		BurstWindowSeconds:   300,
		BurstThreshold:       20,
		BurstCooldownSeconds: 300,

		FIMPollIntervalSeconds: 30,

		TelemetryIntervalSeconds:    30,
		ResourceMemThresholdPercent: 90,
		ResourceLoadThresholdPerCPU: 1.5,

		NetPorts:               []int{8765, 8899, 44700, 8930},
		NetPollIntervalSeconds: 15,

		LimboPollIntervalSeconds: 5,
		LimboAutoQuarantine:      true,
		SarinaCwd:                "/var/lib/heimdall",

		BaselineMinSamples: 20,
		BaselineZThreshold: 3.0,
	}
}

// Load reads a JSON config file over Default(). A missing path is not an
// error -- Default() alone is a valid, if inert, config -- but a malformed
// file is, since a typo silently falling back to defaults would hide a
// misconfiguration from the operator.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalSeconds) * time.Second
}

func (c Config) BurstWindow() time.Duration {
	return time.Duration(c.BurstWindowSeconds) * time.Second
}

func (c Config) BurstCooldown() time.Duration {
	return time.Duration(c.BurstCooldownSeconds) * time.Second
}

func (c Config) FIMPollInterval() time.Duration {
	return time.Duration(c.FIMPollIntervalSeconds) * time.Second
}

func (c Config) TelemetryInterval() time.Duration {
	return time.Duration(c.TelemetryIntervalSeconds) * time.Second
}

func (c Config) NetPollInterval() time.Duration {
	return time.Duration(c.NetPollIntervalSeconds) * time.Second
}

func (c Config) LimboPollInterval() time.Duration {
	return time.Duration(c.LimboPollIntervalSeconds) * time.Second
}
