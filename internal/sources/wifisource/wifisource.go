// Package wifisource reads the results heimdall-wifi-check writes each time a Wi-Fi network is joined (results.jsonl: the network,
// a verdict of safe, caution or unsafe, and the checks behind it) and hands each new one to the detectors. It reads a file; the
// checking itself runs in its own unit, because it has to use the network and heimdalld never does.
package wifisource

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

type check struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type result struct {
	Time     string  `json:"time"`
	SSID     string  `json:"ssid"`
	BSSID    string  `json:"bssid"`
	Security string  `json:"security"`
	Verdict  string  `json:"verdict"`
	Checks   []check `json:"checks"`
}

// Watcher follows the results file from where it stopped (an offset kept next to it).
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
		var res result
		if json.Unmarshal(line, &res) != nil || res.Verdict == "" {
			continue
		}
		var reasons []string
		for _, c := range res.Checks {
			if c.Status == "bad" || c.Status == "warn" {
				reasons = append(reasons, c.Detail)
			}
		}
		t, err := time.Parse(time.RFC3339, res.Time)
		if err != nil {
			t = time.Now()
		}
		ssid := sanitize(res.SSID)
		events = append(events, detect.Event{Source: "host-wifi", Time: t, Kind: "wifi_check",
			Text: fmt.Sprintf("Wi-Fi network %q: %s", ssid, res.Verdict),
			Fields: map[string]string{"ssid": ssid, "bssid": res.BSSID, "security": sanitize(res.Security), "verdict": res.Verdict,
				"reasons": sanitize(strings.Join(reasons, " | ")), "problems": strconv.Itoa(len(reasons))}})
	}
	if err := os.WriteFile(w.OffsetPath, []byte(strconv.FormatInt(off, 10)), 0o600); err != nil {
		return events, err
	}
	return events, nil
}

// sanitize keeps text printable: a network name is chosen by whoever runs the network.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || (r >= 0x200b && r <= 0x200f) {
			return '?'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 600 {
		s = string(r[:600]) + "..."
	}
	return s
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
