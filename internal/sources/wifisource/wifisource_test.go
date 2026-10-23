package wifisource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

func TestResultsBecomeAlertsOnce(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "results.jsonl")
	os.WriteFile(p, []byte(`{"time":"2026-10-23T12:00:00Z","ssid":"Cafe‮Free","verdict":"unsafe","checks":[{"check":"https","status":"bad","detail":"secure connections are being intercepted"},{"check":"firewall","status":"ok","detail":"on"}]}
{"time":"2026-10-23T12:05:00Z","ssid":"Home","verdict":"safe","checks":[]}
{"partial`), 0o600)
	w := &Watcher{Path: p, OffsetPath: filepath.Join(d, "offset")}
	ev, err := w.Poll()
	if err != nil || len(ev) != 2 {
		t.Fatalf("%v %v", ev, err)
	}
	if ev[0].Fields["ssid"] != "Cafe?Free" || ev[0].Fields["reasons"] != "secure connections are being intercepted" {
		t.Errorf("first: %v", ev[0].Fields)
	}
	f := detect.NewWifiDetector().Inspect(ev[0])
	if len(f) != 1 || f[0].Severity != detect.SeverityCritical || !strings.Contains(f[0].Summary, "VPN") {
		t.Errorf("finding: %+v", f)
	}
	if again, _ := w.Poll(); len(again) != 0 {
		t.Error("read twice")
	}
	fh, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`":1}` + "\n" + `{"time":"2026-10-23T13:00:00Z","ssid":"Hotel","verdict":"caution","checks":[{"check":"sign-in","status":"warn","detail":"sign in first"}]}` + "\n")
	fh.Close()
	ev, _ = w.Poll()
	if len(ev) != 1 || ev[0].Fields["verdict"] != "caution" {
		t.Errorf("after append: %+v", ev)
	}
}
