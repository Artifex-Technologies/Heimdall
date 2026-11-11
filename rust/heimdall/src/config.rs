//! heimdalld's configuration: the Go daemon's JSON file, read the way Go reads it (every field optional over the defaults,
//! keys matched without regard to case, unknown keys ignored, a type error refused), so both daemons can run from the same
//! /etc/heimdall/config.json (Go: internal/config).

use crate::gojson;

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub agent_session_dir: String,
    pub agent_state_path: String,
    pub vault_dirs: Vec<String>,
    pub vault_state_path: String,
    pub poll_interval_seconds: i64,
    pub alert_log_path: String,
    pub ring_size: i64,
    pub api_addr: String,
    pub api_users: Vec<String>,
    pub api_groups: Vec<String>,
    pub grant_requests_path: String,
    pub rule_drafts_path: String,
    pub burst_window_seconds: i64,
    pub burst_threshold: i64,
    pub burst_cooldown_seconds: i64,
    pub fim_paths: Vec<String>,
    pub fim_poll_interval_seconds: i64,
    pub fim_state_path: String,
    pub telemetry_interval_seconds: i64,
    pub resource_mem_threshold_percent: f64,
    pub resource_load_threshold_per_cpu: f64,
    pub net_ports: Vec<i64>,
    pub net_poll_interval_seconds: i64,
    pub conn_watch: bool,
    pub conn_poll_interval_seconds: i64,
    pub conn_state_path: String,
    pub app_network_policy: String,
    pub ip_databases: Vec<String>,
    pub threat_list_dir: String,
    pub security_tracker: String,
    pub package_audit_interval_hours: i64,
    pub package_audit_state_path: String,
    pub kernel_vulns: String,
    pub kernel_audit_state_path: String,
    pub hardening_state_path: String,
    pub wifi_results: String,
    pub lan_dir: String,
    pub listen_watch: bool,
    pub firewall: bool,
    pub firewall_poll_interval_seconds: i64,
    pub firewall_cursor_path: String,
    pub maintenance_path: String,
    pub maintenance_actors: Vec<String>,
    pub maintenance_soften: Vec<String>,
    pub pacman_db: String,
    pub limbo_event_log: String,
    pub limbo_state_path: String,
    pub limbo_poll_interval_seconds: i64,
    pub limbo_control_socket: String,
    pub limbo_auto_quarantine: bool,
    pub limbo_quarantine_delay_seconds: i64,
    pub limbo_backlog_threshold: i64,
    pub sarina_url: String,
    pub sarina_token: String,
    pub sarina_cwd: String,
    pub sarina_installed: String,
    pub baseline_min_samples: i64,
    pub baseline_z_threshold: f64,
    pub agent_baseline_state_path: String,
    pub mesh_listen: String,
    pub mesh_dir: String,
    pub mesh_peers_path: String,
    pub mesh_min_severity: String,
}

crate::go_struct!(Config {
    agent_session_dir: "agent_session_dir",
    agent_state_path: "agent_state_path",
    vault_dirs: "vault_dirs",
    vault_state_path: "vault_state_path",
    poll_interval_seconds: "poll_interval_seconds",
    alert_log_path: "alert_log_path",
    ring_size: "ring_size",
    api_addr: "api_addr",
    api_users: "api_users",
    api_groups: "api_groups",
    grant_requests_path: "grant_requests_path",
    rule_drafts_path: "rule_drafts_path",
    burst_window_seconds: "burst_window_seconds",
    burst_threshold: "burst_threshold",
    burst_cooldown_seconds: "burst_cooldown_seconds",
    fim_paths: "fim_paths",
    fim_poll_interval_seconds: "fim_poll_interval_seconds",
    fim_state_path: "fim_state_path",
    telemetry_interval_seconds: "telemetry_interval_seconds",
    resource_mem_threshold_percent: "resource_mem_threshold_percent",
    resource_load_threshold_per_cpu: "resource_load_threshold_per_cpu",
    net_ports: "net_ports",
    net_poll_interval_seconds: "net_poll_interval_seconds",
    conn_watch: "conn_watch",
    conn_poll_interval_seconds: "conn_poll_interval_seconds",
    conn_state_path: "conn_state_path",
    app_network_policy: "app_network_policy",
    ip_databases: "ip_databases",
    threat_list_dir: "threat_list_dir",
    security_tracker: "security_tracker",
    package_audit_interval_hours: "package_audit_interval_hours",
    package_audit_state_path: "package_audit_state_path",
    kernel_vulns: "kernel_vulns",
    kernel_audit_state_path: "kernel_audit_state_path",
    hardening_state_path: "hardening_state_path",
    wifi_results: "wifi_results",
    lan_dir: "lan_dir",
    listen_watch: "listen_watch",
    firewall: "firewall",
    firewall_poll_interval_seconds: "firewall_poll_interval_seconds",
    firewall_cursor_path: "firewall_cursor_path",
    maintenance_path: "maintenance_path",
    maintenance_actors: "maintenance_actors",
    maintenance_soften: "maintenance_soften",
    pacman_db: "pacman_db",
    limbo_event_log: "limbo_event_log",
    limbo_state_path: "limbo_state_path",
    limbo_poll_interval_seconds: "limbo_poll_interval_seconds",
    limbo_control_socket: "limbo_control_socket",
    limbo_auto_quarantine: "limbo_auto_quarantine",
    limbo_quarantine_delay_seconds: "limbo_quarantine_delay_seconds",
    limbo_backlog_threshold: "limbo_backlog_threshold",
    sarina_url: "sarina_url",
    sarina_token: "sarina_token",
    sarina_cwd: "sarina_cwd",
    sarina_installed: "sarina_installed",
    baseline_min_samples: "baseline_min_samples",
    baseline_z_threshold: "baseline_z_threshold",
    agent_baseline_state_path: "agent_baseline_state_path",
    mesh_listen: "mesh_listen",
    mesh_dir: "mesh_dir",
    mesh_peers_path: "mesh_peers_path",
    mesh_min_severity: "mesh_min_severity",
});

fn s(v: &str) -> String {
    v.to_owned()
}

fn list(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

impl Default for Config {
    /// Go's config.Default(), field for field.
    fn default() -> Self {
        Config {
            agent_session_dir: String::new(),
            agent_state_path: s("/var/lib/heimdall/agent-sessions.json"),
            vault_dirs: Vec::new(),
            vault_state_path: s("/var/lib/heimdall/vault-notes.json"),
            poll_interval_seconds: 5,
            alert_log_path: String::new(),
            ring_size: 500,
            api_addr: s("127.0.0.1:8930"),
            api_users: list(&["sarina"]),
            api_groups: list(&["wheel"]),
            grant_requests_path: s("/var/lib/heimdall/grant-requests.json"),
            rule_drafts_path: s("/var/lib/heimdall/rule-drafts.json"),
            burst_window_seconds: 300,
            burst_threshold: 20,
            burst_cooldown_seconds: 300,
            fim_paths: Vec::new(),
            fim_poll_interval_seconds: 30,
            fim_state_path: String::new(),
            telemetry_interval_seconds: 30,
            resource_mem_threshold_percent: 90.0,
            resource_load_threshold_per_cpu: 1.5,
            net_ports: vec![8765, 8899, 44700, 8930],
            net_poll_interval_seconds: 15,
            conn_watch: true,
            conn_poll_interval_seconds: 10,
            conn_state_path: s("/var/lib/heimdall/connections-state.json"),
            app_network_policy: s("/etc/labyrinth/app-network.json"),
            ip_databases: list(&[
                "/var/lib/heimdall/ipdb/ipinfo_lite.mmdb",
                "/var/lib/heimdall/ipdb/dbip-country-lite.mmdb",
                "/var/lib/heimdall/ipdb/dbip-asn-lite.mmdb",
            ]),
            threat_list_dir: s("/var/lib/heimdall/intel"),
            security_tracker: s("/var/lib/heimdall/intel/arch-security.json"),
            package_audit_interval_hours: 6,
            package_audit_state_path: s("/var/lib/heimdall/package-audit.json"),
            kernel_vulns: s("/var/lib/heimdall/intel/linux-kernel.json"),
            kernel_audit_state_path: s("/var/lib/heimdall/kernel-audit.json"),
            hardening_state_path: s("/var/lib/heimdall/hardening.json"),
            wifi_results: s("/var/lib/heimdall/wifi/results.jsonl"),
            lan_dir: s("/var/lib/heimdall/lan"),
            listen_watch: true,
            firewall: true,
            firewall_poll_interval_seconds: 15,
            firewall_cursor_path: s("/var/lib/heimdall/firewall.cursor"),
            maintenance_path: s("/etc/heimdall/maintenance.json"),
            maintenance_actors: Vec::new(),
            maintenance_soften: list(&["file-integrity", "resource-pressure", "baseline-drift", "network-exposure", "connection-watch"]),
            pacman_db: s("/var/lib/pacman/local"),
            limbo_event_log: String::new(),
            limbo_state_path: String::new(),
            limbo_poll_interval_seconds: 5,
            limbo_control_socket: String::new(),
            limbo_auto_quarantine: true,
            limbo_quarantine_delay_seconds: 0,
            limbo_backlog_threshold: 0,
            sarina_url: String::new(),
            sarina_token: String::new(),
            sarina_cwd: s("/var/lib/heimdall"),
            sarina_installed: s("/usr/bin/sarina"),
            baseline_min_samples: 20,
            baseline_z_threshold: 3.0,
            agent_baseline_state_path: s("/var/lib/heimdall/agent-baseline.json"),
            mesh_listen: String::new(),
            mesh_dir: s("/var/lib/heimdall/mesh"),
            mesh_peers_path: s("/etc/heimdall/mesh-peers.json"),
            mesh_min_severity: s("warning"),
        }
    }
}

const SEC: i64 = 1_000_000_000;

impl Config {
    /// Reads a config document over the defaults (Go's config.Load after the file is read).
    pub fn parse(b: &[u8]) -> Result<Config, String> {
        gojson::unmarshal(b, Config::default()).map_err(|e| e.to_string())
    }

    /// `load` with the Go command's error texts word for word, for the one-shot commands that print them (`heimdalld scan`):
    /// a read error as Go's ("config: read P: open P: permission denied") and a type error naming the struct as the Go that
    /// builds heimdalld does ("... into Go struct field Config.ring_size of type int"). The daemon keeps `load`.
    pub fn load_go(path: &str) -> Result<Config, String> {
        if path.is_empty() {
            return Ok(Config::default());
        }
        match std::fs::read(path) {
            Ok(b) => Config::parse(&b).map_err(|e| {
                let e = e.replacen(" into Go struct field ", " into Go struct field Config.", 1);
                format!("config: parse {path}: {}", e.replacen(" into Go value of type Config", " into Go value of type config.Config", 1))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("config: read {path}: {}", crate::gopath::read_err(path, &e))),
        }
    }

    /// Go's config.Load: an empty path or a missing file is the defaults; a file that does not read is an error.
    pub fn load(path: &str) -> Result<Config, String> {
        if path.is_empty() {
            return Ok(Config::default());
        }
        match std::fs::read(path) {
            Ok(b) => Config::parse(&b).map_err(|e| format!("config: parse {path}: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("config: read {path}: {e}")),
        }
    }

    // Durations in nanoseconds, as Go's time.Duration(n) * time.Second (wrapping like Go on overflow).
    pub fn poll_interval(&self) -> i64 {
        self.poll_interval_seconds.wrapping_mul(SEC)
    }
    pub fn burst_window(&self) -> i64 {
        self.burst_window_seconds.wrapping_mul(SEC)
    }
    pub fn burst_cooldown(&self) -> i64 {
        self.burst_cooldown_seconds.wrapping_mul(SEC)
    }
    pub fn fim_poll_interval(&self) -> i64 {
        self.fim_poll_interval_seconds.wrapping_mul(SEC)
    }
    pub fn telemetry_interval(&self) -> i64 {
        self.telemetry_interval_seconds.wrapping_mul(SEC)
    }
    pub fn net_poll_interval(&self) -> i64 {
        self.net_poll_interval_seconds.wrapping_mul(SEC)
    }
    pub fn firewall_poll_interval(&self) -> i64 {
        if self.firewall_poll_interval_seconds <= 0 {
            return 15 * SEC;
        }
        self.firewall_poll_interval_seconds.wrapping_mul(SEC)
    }
    pub fn conn_poll_interval(&self) -> i64 {
        self.conn_poll_interval_seconds.wrapping_mul(SEC)
    }
    pub fn limbo_poll_interval(&self) -> i64 {
        self.limbo_poll_interval_seconds.wrapping_mul(SEC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_over_defaults_as_go_does() {
        let c = Config::parse(br#"{"Agent_Session_Dir":"/s","ring_size":7,"unknown":1,"net_ports":null,"vault_dirs":["a",null]}"#).unwrap();
        assert_eq!(c.agent_session_dir, "/s");
        assert_eq!(c.ring_size, 7);
        assert!(c.net_ports.is_empty(), "null sets a slice to nil in Go");
        assert_eq!(c.vault_dirs, ["a", ""]);
        assert_eq!(c.api_addr, "127.0.0.1:8930");
    }

    #[test]
    fn refuses_what_go_refuses() {
        for bad in
            [&br#"{"ring_size":5.0}"#[..], br#"{"ring_size":"5"}"#, br#"{"conn_watch":1}"#, br#"[1]"#, br#"{"net_ports":[1.5]}"#, b"{"]
        {
            assert!(Config::parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(Config::parse(b"null").is_ok());
    }

    #[test]
    fn the_example_config_reads() {
        let b = include_bytes!("../../../packaging/arch/config.json.example");
        Config::parse(b).unwrap();
    }
}
