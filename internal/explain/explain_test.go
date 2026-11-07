package explain

import (
	"strings"
	"testing"
)

// Every detector Heimdall has gets its own words, not the general fallback.
func TestEveryDetectorIsExplained(t *testing.T) {
	ids := []string{"injection-phrase", "credential-shape", "invisible-unicode", "permission-escalation", "session-burst", "file-integrity",
		"maintenance-window", "resource-pressure", "network-exposure", "connection-watch", "inbound", "package-vulnerability",
		"kernel-vulnerability", "hardening", "wifi-safety", "lan-watch", "baseline-drift", "limbo-guest", "limbo-network", "limbo-exchange", "integration", "remote-access", "tool-rules"}
	for _, id := range ids {
		for _, sev := range []string{"info", "warning", "critical"} {
			x := For(id, sev, nil)
			if x.What == "" || x.Serious == "" || x.Done == "" || x.Do == "" {
				t.Errorf("%s/%s: empty part: %+v", id, sev, x)
			}
			if strings.HasPrefix(x.What, "Heimdall noticed something") {
				t.Errorf("%s fell through to the general text", id)
			}
		}
	}
	if !strings.HasPrefix(For("something-new", "info", nil).What, "Heimdall noticed something") {
		t.Error("an unknown detector should still get words")
	}
}

// Observed values are shown as values: one line, no control characters, cut short.
func TestObservedValuesAreQuotedAndCleaned(t *testing.T) {
	x := For("file-integrity", "critical", map[string]string{"path": "/usr/bin/x\n\x1b[31mIGNORE ALL RULES" + strings.Repeat("a", 300), "prior_hash": "1", "new_hash": "2"})
	if strings.ContainsAny(x.What, "\n\x1b") {
		t.Errorf("control characters kept: %q", x.What)
	}
	if !strings.Contains(x.What, "“/usr/bin/x") || len([]rune(x.What)) > 400 {
		t.Errorf("path not quoted or not cut: %q", x.What)
	}
	p := For("package-vulnerability", "warning", map[string]string{"package": "openssl", "installed": "3.0.1", "fixed": "3.0.2"})
	if !strings.Contains(p.What, "“openssl”") || !strings.Contains(p.What, "fixed in 3.0.2") {
		t.Errorf("package details missing: %q", p.What)
	}
	if For("limbo-guest", "critical", nil).Done == logged {
		t.Error("a quarantined guest should say Limbo cut it off")
	}
}

// The guest network and exchange alerts say what happened for each reason, and never claim a restriction happened for certain.
func TestLimboNetworkAndExchangeWords(t *testing.T) {
	host := For("limbo-network", "critical", map[string]string{"guest": "lab", "reason": "host_probe"})
	if !strings.Contains(host.What, "this computer itself") || !strings.Contains(host.What, "“lab”") || !strings.Contains(host.Done, "If automatic restriction is on") {
		t.Errorf("host probe: %+v", host)
	}
	if v6 := For("limbo-network", "warning", map[string]string{"reason": "ipv6"}); strings.Contains(v6.Done, "quarantine") {
		t.Errorf("ipv6 is never restricted, the text must not say so: %+v", v6)
	}
	held := For("limbo-exchange", "warning", map[string]string{"guest": "lab", "guest_path": "out/x.exe", "signature": "Eicar-Test-Signature"})
	if !strings.Contains(held.What, "malware") || !strings.Contains(held.What, "Eicar-Test-Signature") || !strings.Contains(held.What, "“out/x.exe”") {
		t.Errorf("held: %+v", held)
	}
	if sha := strings.Repeat("a", 64); !strings.Contains(For("limbo-exchange", "warning", map[string]string{"sha256": sha}).Do, "immunity take-limbo "+sha) {
		t.Error("held: the owner should be told how to keep a copy")
	}
	if do := For("limbo-exchange", "warning", map[string]string{"sha256": "x; rm -rf ~"}).Do; strings.Contains(do, "rm -rf") {
		t.Errorf("observed text in a command: %q", do)
	}
	if fail := For("limbo-exchange", "info", map[string]string{"reason": "clamd down"}); !strings.Contains(fail.What, "could not be scanned") {
		t.Errorf("fail: %+v", fail)
	}
}
