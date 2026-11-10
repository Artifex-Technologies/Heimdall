"""The shadow daemon's config from the Go daemon's: the same sources, every file it writes moved from /var/lib/heimdall/ to
/var/lib/heimdall-rs/, the API off (the Go daemon serves it).

    python3 -I shadow-config.py /etc/heimdall/config.json > shadow-config.json

The defaults the Go config leaves out are written in too, so no path falls back to /var/lib/heimdall/.
"""
import json, sys

GO, RS = "/var/lib/heimdall/", "/var/lib/heimdall-rs/"
# the files a daemon writes, with the Go daemon's defaults (internal/config/config.go)
WRITTEN = {
    "agent_state_path": "/var/lib/heimdall/agent-sessions.json",
    "vault_state_path": "/var/lib/heimdall/vault-notes.json",
    "alert_log_path": "",
    "fim_state_path": "",
    "limbo_state_path": "",
    "agent_baseline_state_path": "/var/lib/heimdall/agent-baseline.json",
    "conn_state_path": "/var/lib/heimdall/connections-state.json",
    "firewall_cursor_path": "/var/lib/heimdall/firewall.cursor",
    "package_audit_state_path": "/var/lib/heimdall/package-audit.json",
    "kernel_audit_state_path": "/var/lib/heimdall/kernel-audit.json",
    "hardening_state_path": "/var/lib/heimdall/hardening.json",
    "grant_requests_path": "/var/lib/heimdall/grant-requests.json",
    "rule_drafts_path": "/var/lib/heimdall/rule-drafts.json",
    "mesh_dir": "/var/lib/heimdall/mesh",
}

cfg = json.load(open(sys.argv[1]))
lower = {k.lower(): k for k in cfg}  # Go reads keys without regard to case
for key, default in WRITTEN.items():
    k = lower.get(key, key)
    v = cfg.get(k, default)
    if isinstance(v, str) and v.startswith(GO):
        v = RS + v[len(GO):]
    if key == "alert_log_path" and not v:
        v = RS + "alerts.jsonl"  # the shadow week is compared on this file
    cfg[k] = v
cfg[lower.get("api_addr", "api_addr")] = ""
json.dump(cfg, sys.stdout, indent=1)
print()
