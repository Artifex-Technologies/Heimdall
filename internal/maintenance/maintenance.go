// Package maintenance is the owner's "I am changing the system" window. While it is open, Heimdall
// turns the alerts that routine administration causes (a changed system file, a CPU spike, a new network
// destination) from warnings into info notes, still written to the log; everything that is about
// content (prompt injection, credentials, hidden characters, escalation) is NOT touched, and neither
// is anything about Limbo guests. A window has a reason, who opened it, and an end time that cannot be
// more than MaxDuration away, so it always closes by itself.
//
// The window is a small JSON file in a root-owned folder (default /etc/heimdall/maintenance.json):
// Heimdall only reads it, so nothing Heimdall watches (Sarina, a guest) can open one.
package maintenance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxDuration is the longest a window may stay open.
const MaxDuration = 4 * time.Hour

type Window struct {
	Reason string    `json:"reason"`
	Actor  string    `json:"actor"`
	Opened time.Time `json:"opened"`
	Until  time.Time `json:"until"`
}

// Active reports whether the window is open at t.
func (w Window) Active(t time.Time) bool { return !w.Until.IsZero() && t.Before(w.Until) }

// Open builds a window of length d (capped at MaxDuration) from now.
func Open(actor, reason string, d time.Duration, now time.Time) (Window, error) {
	if d <= 0 {
		return Window{}, errors.New("maintenance: the duration must be positive")
	}
	if d > MaxDuration {
		d = MaxDuration
	}
	if reason == "" {
		return Window{}, errors.New("maintenance: a reason is required")
	}
	return Window{Reason: reason, Actor: actor, Opened: now, Until: now.Add(d)}, nil
}

// Write saves the window atomically.
func Write(path string, w Window) error {
	raw, err := json.Marshal(w)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Clear closes the window.
func Clear(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Read returns the window in the file (found false when there is none or it cannot be read).
func Read(path string) (w Window, found bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Window{}, false
	}
	if json.Unmarshal(raw, &w) != nil {
		return Window{}, false
	}
	// a hand-edited file may not exceed the cap
	if !w.Opened.IsZero() && w.Until.Sub(w.Opened) > MaxDuration {
		w.Until = w.Opened.Add(MaxDuration)
	}
	return w, true
}

// Watcher re-reads the file at most every two seconds, so the engine can ask on every event.
type Watcher struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
	last time.Time
	win  Window
	ok   bool
}

func NewWatcher(path string) *Watcher { return &Watcher{path: path, now: time.Now} }

// Active returns the open window, if any.
func (m *Watcher) Active() (Window, bool) {
	if m == nil || m.path == "" {
		return Window{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.now()
	if t.Sub(m.last) > 2*time.Second {
		m.win, m.ok = Read(m.path)
		m.last = t
	}
	if m.ok && m.win.Active(t) {
		return m.win, true
	}
	return Window{}, false
}

// Describe is the one-line status text.
func Describe(w Window, found bool, now time.Time) string {
	if !found || !w.Active(now) {
		return "no maintenance window is open"
	}
	return fmt.Sprintf("maintenance window open: %q, opened by %s, %s left (ends %s)", w.Reason, w.Actor, w.Until.Sub(now).Round(time.Minute), w.Until.Format("15:04"))
}

// Dir is the folder of the file (for callers that create it).
func Dir(path string) string { return filepath.Dir(path) }
