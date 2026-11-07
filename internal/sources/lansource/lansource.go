// Package lansource follows the device list's record of new devices (events.jsonl, written by heimdall-lan-scan through
// internal/lan) and hands each to the detectors. It reads a file; the looking around runs in its own unit, because it has to use
// the network and heimdalld never does.
package lansource

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/lan"
)

// Watcher follows the file from where it stopped (an offset kept next to it).
type Watcher struct {
	Path, OffsetPath string
}

func (w *Watcher) Poll() ([]detect.Event, error) {
	f, err := os.Open(w.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var off int64
	if b, err := os.ReadFile(w.OffsetPath); err == nil {
		off, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	if st, err := f.Stat(); err == nil && st.Size() < off {
		off = 0 // the file was replaced
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	var events []detect.Event
	r := bufio.NewReader(io.LimitReader(f, 4<<20))
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break // a line still being written waits for the next poll
		}
		off += int64(len(line))
		var nd lan.NewDevice
		if json.Unmarshal(line, &nd) != nil || nd.Device.MAC == "" {
			continue
		}
		d := nd.Device
		events = append(events, detect.Event{Source: "host-lan", Time: nd.Time, Kind: "new_lan_device",
			Text: "a new device on " + nd.SSID + ": " + d.IP,
			Fields: map[string]string{"ssid": nd.SSID, "ip": d.IP, "mac": d.MAC, "vendor": d.Vendor, "name": d.Name,
				"model": d.Model, "kind": d.Kind, "private_mac": strconv.FormatBool(d.PrivateMAC)}})
	}
	if err := os.WriteFile(w.OffsetPath, []byte(strconv.FormatInt(off, 10)), 0o600); err != nil {
		return events, err
	}
	return events, nil
}

func (w *Watcher) Run(ctx context.Context, interval time.Duration, onErr func(error), emit func(detect.Event)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		events, err := w.Poll()
		if err != nil {
			onErr(err)
		}
		for _, e := range events {
			emit(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
