"""The synthetic environment for a side-by-side run of two heimdalld daemons (made-up data only). A cleaned copy of the
phase-0 harness (docs/ARCHITECTURE.md "Running light"), for the Go daemon and its Rust port.

    python3 -I setup-env.py ENV_DIR [--network]

ENV_DIR/sessions: 6,629 session files plus 482 lock files and an agent/ folder with 12 sessions (as on the owner's PC: the
count, not the content); fim/: 25 files of 8000 bytes; limbo/events.jsonl; vault/ with three notes; go/ and rust/: each
daemon's own config and state. The host's own load and memory are not synthetic, so their alerts are switched off in both.
Without --network the /proc/net watchers, the journal and the audits are off in both (the Rust port's step 2 has not
ported them yet); with it they are on, as in phase 0 (run inside `unshare -rn`, see side-by-side.sh).
"""
import json, os, shutil, sys

env = sys.argv[1]
network = "--network" in sys.argv
if os.path.exists(env):
    shutil.rmtree(env)
S = os.path.join(env, "sessions")
os.makedirs(os.path.join(S, "agent"))
body = json.dumps({"session_id": "x", "messages": ["hello", "world", "a tool result", "done"], "runtime_config": {"cwd": "/home/u"}})
for i in range(6629):
    with open(os.path.join(S, "%032x.json" % i), "w") as f:
        f.write(body)
for i in range(482):
    open(os.path.join(S, "%032x.json.lock" % i), "w").close()
for i in range(12):
    with open(os.path.join(S, "agent", "a%02d.json" % i), "w") as f:
        json.dump({"session_id": "a%02d" % i, "messages": [{"role": "user", "content": "summarise the build log"},
                                                            {"role": "assistant", "content": "The build passed."}]}, f)
os.makedirs(os.path.join(env, "fim"))
for i in range(25):
    with open(os.path.join(env, "fim", "f%02d" % i), "w") as f:
        f.write("x" * 8000)
os.makedirs(os.path.join(env, "limbo"))
with open(os.path.join(env, "limbo", "events.jsonl"), "w") as f:
    f.write(json.dumps({"time": "2026-11-09T08:00:00Z", "kind": "policy.apply", "guest": "g-old", "detail": {"level": "default"}}) + "\n")
os.makedirs(os.path.join(env, "vault", "notes"))
for i in range(3):
    with open(os.path.join(env, "vault", "notes", "n%d.md" % i), "w") as f:
        f.write("# Note %d\n\nShopping list and plans for the weekend.\n" % i)

for name in ("go", "rust"):
    d = os.path.join(env, name)
    os.makedirs(os.path.join(d, "intel"))
    cfg = {
        "agent_session_dir": S,
        "agent_state_path": os.path.join(d, "agent-sessions.json"),
        "poll_interval_seconds": 5,
        "alert_log_path": os.path.join(d, "alerts.jsonl"),
        "ring_size": 500,
        "api_addr": "",
        "grant_requests_path": os.path.join(d, "grant-requests.json"),
        "rule_drafts_path": os.path.join(d, "rule-drafts.json"),
        "fim_paths": [os.path.join(env, "fim", "f%02d" % i) for i in range(25)],
        "fim_poll_interval_seconds": 30,
        "fim_state_path": os.path.join(d, "fim.json"),
        "telemetry_interval_seconds": 30,
        "resource_mem_threshold_percent": 101,
        "resource_load_threshold_per_cpu": 1000,
        "baseline_min_samples": 1000000,
        "net_ports": [8765, 8899, 44700, 8930] if network else [],
        "net_poll_interval_seconds": 15,
        "conn_watch": network,
        "conn_poll_interval_seconds": 10,
        "conn_state_path": os.path.join(d, "conn.json"),
        "app_network_policy": os.path.join(d, "no-policy.json"),
        "ip_databases": [os.path.join(env, "ipdb", "dbip-country-lite.mmdb"), os.path.join(env, "ipdb", "dbip-asn-lite.mmdb")],
        "threat_list_dir": os.path.join(d, "intel"),
        "security_tracker": os.path.join(d, "intel", "arch-security.json") if network else "",
        "package_audit_state_path": os.path.join(d, "pkg.json"),
        "kernel_vulns": os.path.join(d, "intel", "linux-kernel.json") if network else "",
        "kernel_audit_state_path": os.path.join(d, "kern.json"),
        "hardening_state_path": os.path.join(d, "hard.json") if network else "",
        "wifi_results": os.path.join(d, "wifi", "results.jsonl") if network else "",
        "lan_dir": os.path.join(d, "lan") if network else "",
        "listen_watch": network,
        "firewall": False,
        "firewall_cursor_path": os.path.join(d, "firewall.cursor"),
        "maintenance_path": os.path.join(d, "maintenance.json"),
        "agent_baseline_state_path": os.path.join(d, "agent-baseline.json"),
        "vault_dirs": [os.path.join(env, "vault")],
        "vault_state_path": os.path.join(d, "vault.json"),
        "mesh_dir": os.path.join(d, "mesh"),
        "mesh_peers_path": os.path.join(d, "mesh-peers.json"),
        "limbo_event_log": os.path.join(env, "limbo", "events.jsonl"),
        "limbo_state_path": os.path.join(d, "limbo-offset"),
        "limbo_poll_interval_seconds": 5,
        "sarina_installed": "/nonexistent",
    }
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(cfg, f, indent=1)
print("environment ready in", env)
