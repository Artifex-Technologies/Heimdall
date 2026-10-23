package pkgaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Watcher checks the installed packages against the tracker file now and then, and reports each finding once (until the package
// version changes). The first check after start reports what is open, so a vulnerable package is never silently assumed known.
type Watcher struct {
	TrackerPath, PacmanDB, StatePath string
}

func (w *Watcher) Poll() ([]detect.Event, error) {
	groups, err := LoadTracker(w.TrackerPath)
	if err != nil {
		return nil, err
	}
	inst, err := Installed(w.PacmanDB)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	if b, err := os.ReadFile(w.StatePath); err == nil {
		_ = json.Unmarshal(b, &seen)
	}
	now := time.Now()
	current := map[string]bool{}
	var events []detect.Event
	for _, f := range Check(groups, inst) {
		current[f.Key()] = true
		if seen[f.Key()] {
			continue
		}
		fix := "fixed in " + f.Group.Fixed
		if f.NoFix {
			fix = "no fixed version yet"
		}
		events = append(events, detect.Event{Source: "host-packages", Time: now, Kind: "vulnerable_package",
			Text: fmt.Sprintf("%s %s is installed and has a known %s vulnerability (%s, %s; %s)", f.Package, f.Installed,
				strings.ToLower(f.Group.Severity), f.Group.Name, strings.Join(f.Group.Issues, " "), fix),
			Fields: map[string]string{"package": f.Package, "installed": f.Installed, "fixed": f.Group.Fixed, "severity": f.Group.Severity,
				"advisory": f.Group.Name, "cves": strings.Join(f.Group.Issues, " "), "type": f.Group.Type, "no_fix": fmt.Sprint(f.NoFix)}})
	}
	// remember only what is still open: a package updated and later vulnerable again is reported again
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
