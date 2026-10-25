package kernelaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Watcher compares the installed kernels with the list now and then and reports each kernel once (again when what is open
// changes).
type Watcher struct {
	ListPath, ModulesDir, StatePath string
	Running                         string // the running kernel (uname -r); empty: asked of the system
}

// Running is the running kernel (uname -r).
func Running() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	var b strings.Builder
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}

func (w *Watcher) Poll() ([]detect.Event, error) {
	f, err := Load(w.ListPath)
	if err != nil {
		return nil, err
	}
	run := w.Running
	if run == "" {
		run = Running()
	}
	seen := map[string]bool{}
	if b, err := os.ReadFile(w.StatePath); err == nil {
		_ = json.Unmarshal(b, &seen)
	}
	current := map[string]bool{}
	var events []detect.Event
	for _, k := range Installed(w.ModulesDir) {
		holes, fixAll := Check(f, k)
		if len(holes) == 0 {
			continue
		}
		key := fmt.Sprintf("%s|%d|%s", k, len(holes), holes[0].ID)
		current[key] = true
		if seen[key] {
			continue
		}
		var ids, exploited []string
		scored, sameLine := 0, 0
		lineFix := ""
		for _, h := range holes {
			if len(ids) < 8 {
				ids = append(ids, h.ID)
			}
			if h.Score >= 7 {
				scored++
			}
			if h.Exploited {
				exploited = append(exploited, h.ID)
			}
			if h.SameLine {
				sameLine++
				if lineFix == "" || Compare(Version(h.FixedIn), Version(lineFix)) > 0 {
					lineFix = h.FixedIn
				}
			}
		}
		worst := holes[0]
		events = append(events, detect.Event{Source: "host-kernel", Time: time.Now(), Kind: "vulnerable_kernel",
			Text: fmt.Sprintf("kernel %s has %d known hole(s) fixed in %s; worst %s (%.1f): %s", k, len(holes), fixAll, worst.ID, worst.Score, worst.Summary),
			Fields: map[string]string{"kernel": k, "running": fmt.Sprint(k == run), "count": fmt.Sprint(len(holes)), "high": fmt.Sprint(scored),
				"fixed": fixAll, "worst": worst.ID, "worst_score": fmt.Sprintf("%.1f", worst.Score), "worst_summary": worst.Summary,
				"cves": strings.Join(ids, " "), "exploited": strings.Join(exploited, " "), "same_line": fmt.Sprint(sameLine), "line_fix": lineFix}})
	}
	b, _ := json.Marshal(current)
	tmp := w.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, w.StatePath)
	}
	return events, nil
}

func (w *Watcher) Run(ctx context.Context, interval time.Duration, onErr func(error), emit func(detect.Event)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		events, err := w.Poll()
		if err != nil && !os.IsNotExist(err) {
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
