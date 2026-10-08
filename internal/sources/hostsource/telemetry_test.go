package hostsource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMemInfo(t *testing.T) {
	// A real /proc/meminfo has many more lines; only these two matter here.
	sample := `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
`
	total, avail, err := ParseMemInfo(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("ParseMemInfo: %v", err)
	}
	if total != 16384000 {
		t.Fatalf("expected total 16384000, got %d", total)
	}
	if avail != 8192000 {
		t.Fatalf("expected available 8192000, got %d", avail)
	}
}

func TestParseMemInfoMissingTotal(t *testing.T) {
	_, _, err := ParseMemInfo(strings.NewReader("MemFree: 1024 kB\n"))
	if err == nil {
		t.Fatal("expected an error when MemTotal is missing")
	}
}

func TestParseLoadAvg(t *testing.T) {
	load1, err := ParseLoadAvg(strings.NewReader("1.25 0.90 0.75 2/512 12345\n"))
	if err != nil {
		t.Fatalf("ParseLoadAvg: %v", err)
	}
	if load1 != 1.25 {
		t.Fatalf("expected load1 1.25, got %v", load1)
	}
}

func TestTelemetryWatcherPoll(t *testing.T) {
	dir := t.TempDir()
	memPath := filepath.Join(dir, "meminfo")
	loadPath := filepath.Join(dir, "loadavg")

	if err := os.WriteFile(memPath, []byte("MemTotal: 1000 kB\nMemAvailable: 250 kB\n"), 0o600); err != nil {
		t.Fatalf("write meminfo fixture: %v", err)
	}
	if err := os.WriteFile(loadPath, []byte("4.0 3.0 2.0 1/10 999\n"), 0o600); err != nil {
		t.Fatalf("write loadavg fixture: %v", err)
	}

	w := newTelemetryWatcherWithPaths(memPath, loadPath, 2)
	ev, err := w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if ev.Kind != "host_telemetry" {
		t.Fatalf("expected kind host_telemetry, got %q", ev.Kind)
	}
	if ev.Fields["mem_percent"] != "75.00" { // 100 * (1 - 250/1000)
		t.Fatalf("expected mem_percent 75.00, got %q", ev.Fields["mem_percent"])
	}
	if ev.Fields["load_per_cpu"] != "2.00" { // 4.0 / 2 CPUs
		t.Fatalf("expected load_per_cpu 2.00, got %q", ev.Fields["load_per_cpu"])
	}
}

func TestTelemetryWatcherPollMissingProc(t *testing.T) {
	w := newTelemetryWatcherWithPaths(filepath.Join(t.TempDir(), "does-not-exist"), "", 1)
	if _, err := w.Poll(); err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected an os.IsNotExist error, got %v", err)
	}
}
