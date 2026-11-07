package response

import (
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

func netAlert(reason, guest string, sev detect.Severity) alert.Alert {
	return alert.Alert{
		DetectorID: "limbo-network", Severity: sev, Summary: "guest reached for this computer itself",
		Source: "limbo", EventKind: "net.anomaly", EventText: "limbo net.anomaly guest=" + guest + " reason=" + reason,
		Fields: map[string]string{"guest": guest, "reason": reason, "proto": "tcp", "dst": "192.0.2.1", "dport": "22"},
	}
}

// Probing the host, the home network, or scanning restricts the guest; everything else from Limbo's network events is an
// alert only. Every alert is forwarded either way.
func TestNetworkAnomaliesThatRestrict(t *testing.T) {
	tests := []struct {
		name     string
		a        alert.Alert
		wantQuar bool
	}{
		{"host probe", netAlert("host_probe", "lab", detect.SeverityCritical), true},
		{"lan probe", netAlert("lan_probe", "lab", detect.SeverityCritical), true},
		{"scan", netAlert("scan", "lab", detect.SeverityWarning), true},
		{"ipv6 is an alert only", netAlert("ipv6", "lab", detect.SeverityWarning), false},
		{"a reason this Heimdall does not know is an alert only", netAlert("something_new", "lab", detect.SeverityWarning), false},
		{"softened to info by a maintenance window", netAlert("host_probe", "lab", detect.SeverityInfo), false},
		{"capped is an alert only", func() alert.Alert {
			a := netAlert("", "lab", detect.SeverityInfo)
			a.EventKind = "net.capped"
			return a
		}(), false},
		{"from a mesh peer, not Limbo", func() alert.Alert {
			a := netAlert("host_probe", "lab", detect.SeverityCritical)
			a.Source = "mesh"
			return a
		}(), false},
		{"hostile guest name", netAlert("host_probe", "../x;rm", detect.SeverityCritical), false},
		{"a held malware file restricts too (owner, 2026-11-05)", func() alert.Alert {
			a := netAlert("", "lab", detect.SeverityWarning)
			a.DetectorID, a.EventKind = "limbo-exchange", "exchange.held"
			return a
		}(), true},
		{"a file that could not be scanned is an alert only", func() alert.Alert {
			a := netAlert("", "lab", detect.SeverityInfo)
			a.DetectorID, a.EventKind = "limbo-exchange", "exchange.fail"
			return a
		}(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			down, lim := &sink{}, &fakeLimbo{res: Result{Applied: true, Created: true, Record: Record{ID: "q-1"}}}
			r := &Responder{Next: down, Limbo: lim}
			if err := r.Write(tc.a); err != nil {
				t.Fatal(err)
			}
			r.Wait()
			if len(down.got) != 1 {
				t.Fatalf("alert not forwarded exactly once: %d", len(down.got))
			}
			if (len(lim.quarGuest) == 1) != tc.wantQuar {
				t.Fatalf("quarantine calls=%v want=%v", lim.quarGuest, tc.wantQuar)
			}
			if tc.wantQuar {
				if want := "lab|heimdall:" + tc.a.DetectorID; lim.quarGuest[0] != want {
					t.Fatalf("wrong call: %v", lim.quarGuest)
				}
				if lim.explained["q-1"] == "" {
					t.Fatal("Heimdall's own explanation was not attached to the new quarantine")
				}
			}
		})
	}
}

// A stop or a re-applied policy clears a missing-firewall trigger, but not a probe: the guest still went looking for a way
// out, and Limbo will not start a guest it holds.
func TestAProbeIsNotClearedByAStopOrAFreshPolicy(t *testing.T) {
	for _, later := range []string{"guest.stop", "policy.apply"} {
		t.Run(later, func(t *testing.T) {
			next, lim := &recSink{}, newQLimbo(true)
			r := &Responder{Next: next, Limbo: lim}
			saturate(t, r, lim)
			a := netAlert("host_probe", "lab", detect.SeverityCritical)
			a.Time = time.Now()
			r.Write(a)
			r.Observe(detect.Event{Source: "limbo", Kind: later, Fields: map[string]string{"guest": "lab"}})
			close(lim.release)
			r.Wait()
			sent := false
			for _, g := range lim.guests() {
				sent = sent || g == "lab"
			}
			if !sent {
				t.Fatalf("the probe was skipped after %s", later)
			}
			if count(next, CodeQuarantineSkipped) != 0 {
				t.Fatal("a skip note was recorded")
			}
		})
	}
}
