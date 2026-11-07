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
