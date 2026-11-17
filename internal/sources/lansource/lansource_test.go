package lansource

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/lan"
)

func TestNewDevicesBecomeWarnings(t *testing.T) {
	dir := t.TempDir()
	w := &Watcher{Path: filepath.Join(dir, "events.jsonl"), OffsetPath: filepath.Join(dir, "events.offset")}
	line := func(d lan.Device) string {
		b, _ := json.Marshal(lan.NewDevice{Time: time.Now(), SSID: "Home", Device: d})
		return string(b) + "\n"
	}
	os.WriteFile(w.Path, []byte(line(lan.Device{MAC: "00:11:22:33:44:55", IP: "192.168.1.20", Vendor: "Samsung Electronics", Name: "TV"})+
		line(lan.Device{MAC: "DA:00:00:00:00:01", IP: "192.168.1.40", PrivateMAC: true})+`{"half`), 0o600)
	ev, err := w.Poll()
	if err != nil || len(ev) != 2 {
		t.Fatalf("%v %d (a half-written line waits)", err, len(ev))
	}
	d := detect.NewLANDetector()
	f := d.Inspect(ev[0])
	if len(f) != 1 || f[0].Severity != detect.SeverityWarning || !strings.Contains(f[0].Summary, `"Home": TV, made by Samsung Electronics, at 192.168.1.20`) {
		t.Fatalf("%+v", f)
	}
	if f := d.Inspect(ev[1]); len(f) != 1 || !strings.Contains(f[0].Summary, "a device, using a private address") {
		t.Fatalf("%+v", f)
	}
	if ev, _ := w.Poll(); len(ev) != 0 {
		t.Fatal("lines already read are not read again")
	}
}

// TestATakenAddressIsCritical: a line of lan.Takeovers becomes a lan_device_changed event and a critical alert. The Rust
// port parses the same line (rust/heimdall/src/sources/files.rs, a_taken_address_line).
func TestATakenAddressIsCritical(t *testing.T) {
	dir := t.TempDir()
	w := &Watcher{Path: filepath.Join(dir, "events.jsonl"), OffsetPath: filepath.Join(dir, "events.offset")}
	b, _ := json.Marshal(lan.NewDevice{Time: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC), SSID: "Home",
		Device: lan.Device{MAC: "02:00:00:00:00:66", IP: "192.0.2.30"}, Change: "address_taken", WasMAC: "02:00:00:00:00:30", WasName: "TV", OtherIP: "192.0.2.66"})
	if want := `{"time":"2026-11-16T10:00:00Z","ssid":"Home","device":{"mac":"02:00:00:00:00:66","ip":"192.0.2.30","kind":"","first_seen":"0001-01-01T00:00:00Z","last_seen":"0001-01-01T00:00:00Z"},"change":"address_taken","was_mac":"02:00:00:00:00:30","was_name":"TV","other_ip":"192.0.2.66"}`; string(b) != want {
		t.Fatalf("line\n got %s\nwant %s", b, want)
	}
	os.WriteFile(w.Path, append(b, '\n'), 0o600)
	ev, _ := w.Poll()
	if len(ev) != 1 || ev[0].Kind != "lan_device_changed" || ev[0].Fields["was_name"] != "TV" || ev[0].Fields["other_ip"] != "192.0.2.66" {
		t.Fatalf("%+v", ev)
	}
	f := detect.NewLANDetector().Inspect(ev[0])
	if len(f) != 1 || f[0].Severity != detect.SeverityCritical || !strings.Contains(f[0].Summary, "the address 192.0.2.30 of TV (02:00:00:00:00:30)") {
		t.Fatalf("%+v", f)
	}
}
