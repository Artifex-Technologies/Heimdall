// Package hostsource produces detect.Events from the host Heimdall (and
// Sarina) runs on: file integrity (fim.go) and resource telemetry (this
// file). Both are Linux-only by construction -- Heimdall targets
// Arch specifically, see docs/ARCHITECTURE.md's "Arch, specifically" --
// and both read stdlib-parseable /proc text rather than shelling out to
// ps/top or linking a metrics library, the same discipline Netdata's own
// collectors follow for the same reason: a security daemon's own resource
// footprint should be negligible.
package hostsource

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// ParseMemInfo reads /proc/meminfo's text format and returns total and
// available memory in KiB. MemAvailable (not MemFree) is used to compute
// pressure -- it already accounts for reclaimable page cache the kernel
// would hand back under pressure before the host is actually short of
// memory, which MemFree does not.
func ParseMemInfo(r io.Reader) (totalKB, availKB uint64, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			totalKB, err = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable":
			availKB, err = strconv.ParseUint(fields[1], 10, 64)
		}
		if err != nil {
			return 0, 0, fmt.Errorf("hostsource: parse meminfo: %w", err)
		}
	}
	if totalKB == 0 {
		return 0, 0, fmt.Errorf("hostsource: meminfo had no MemTotal line")
	}
	return totalKB, availKB, scanner.Err()
}

// ParseLoadAvg reads /proc/loadavg's text format and returns the 1-minute
// load average (the file's first field).
func ParseLoadAvg(r io.Reader) (load1 float64, err error) {
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		return 0, fmt.Errorf("hostsource: read loadavg: %w", err)
	}
	fields := strings.Fields(buf.String())
	if len(fields) < 1 {
		return 0, fmt.Errorf("hostsource: loadavg had no fields")
	}
	load1, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("hostsource: parse loadavg: %w", err)
	}
	return load1, nil
}

// TelemetryWatcher polls host memory and load telemetry into
// detect.Events. Load average, not a /proc/stat jiffy-delta computation,
// is the CPU pressure signal here: it needs only one read (no previous
// sample to keep around), and load-per-core past 1.0 is a well-understood
// "more runnable work than the host can execute right now" signal --
// exactly the pressure signal Heimdall's own reliability story needs, at a
// fraction of the bookkeeping a precise per-core percentage would cost.
type TelemetryWatcher struct {
	memInfoPath string
	loadAvgPath string
	numCPU      int
}

func NewTelemetryWatcher() *TelemetryWatcher {
	return newTelemetryWatcherWithPaths("/proc/meminfo", "/proc/loadavg", runtime.NumCPU())
}

// newTelemetryWatcherWithPaths lets tests point Poll at fixture files
// instead of real /proc, which doesn't exist on the non-Linux platforms
// this is developed and tested on.
func newTelemetryWatcherWithPaths(memInfoPath, loadAvgPath string, numCPU int) *TelemetryWatcher {
	return &TelemetryWatcher{memInfoPath: memInfoPath, loadAvgPath: loadAvgPath, numCPU: numCPU}
}

// Poll reads current telemetry into a single host_telemetry Event.
// Returns an error unmodified from the underlying file open/read so
// callers can distinguish "no /proc on this platform" (os.IsNotExist) from
// a real parse failure.
func (w *TelemetryWatcher) Poll() (detect.Event, error) {
	memFile, err := os.Open(w.memInfoPath)
	if err != nil {
		return detect.Event{}, err
	}
	defer memFile.Close()
	totalKB, availKB, err := ParseMemInfo(memFile)
	if err != nil {
		return detect.Event{}, err
	}
	memPercent := 100 * (1 - float64(availKB)/float64(totalKB))

	loadFile, err := os.Open(w.loadAvgPath)
	if err != nil {
		return detect.Event{}, err
	}
	defer loadFile.Close()
	load1, err := ParseLoadAvg(loadFile)
	if err != nil {
		return detect.Event{}, err
	}
	loadPerCPU := load1
	if w.numCPU > 0 {
		loadPerCPU = load1 / float64(w.numCPU)
	}

	return detect.Event{
		Source: "host-telemetry",
		Time:   time.Now(),
		Kind:   "host_telemetry",
		Fields: map[string]string{
			"mem_percent":  strconv.FormatFloat(memPercent, 'f', 2, 64),
			"load_per_cpu": strconv.FormatFloat(loadPerCPU, 'f', 2, 64),
		},
	}, nil
}

// Run polls on an interval until ctx is done. If the very first poll fails
// because /proc doesn't exist on this platform (Windows in development;
// any non-Linux target), it logs once and returns instead of retrying
// forever -- there is nothing a retry would fix.
func (w *TelemetryWatcher) Run(ctx context.Context, interval time.Duration, onUnavailable func(error), onErr func(error), emit func(detect.Event)) {
	if _, err := w.Poll(); err != nil {
		if os.IsNotExist(err) {
			if onUnavailable != nil {
				onUnavailable(err)
			}
			return
		}
		if onErr != nil {
			onErr(err)
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ev, err := w.Poll()
			if err != nil {
				if onErr != nil {
					onErr(err)
				}
				continue
			}
			emit(ev)
		}
	}
}
