package contain

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Trigger passes every alert on and, when automatic containment is on, turns a critical finding about the AI agents into a
// request for the root unit: an unapproved change to their behaviour files (trust), or a session that keeps asking for tools
// its tier does not allow (escalation). An injection phrase alone does not: it is often only text she read (a web page). At most one request every ten minutes, and none while the lock is already there.
type Trigger struct {
	Next        alert.Sink
	ConfigPath  string
	RequestPath string
	MarkerPath  string

	mu   sync.Mutex
	last time.Time
}

// AboutAgents reports whether an alert is the kind that warrants containing the AI.
func AboutAgents(a alert.Alert) bool {
	if a.Severity != detect.SeverityCritical {
		return false
	}
	switch a.DetectorID {
	case "file-integrity":
		return strings.Contains(a.Summary, "decides how an AI agent behaves")
	case "permission-escalation":
		return a.Source == "agent-session"
	}
	return false
}

func (t *Trigger) Write(a alert.Alert) error {
	err := t.Next.Write(a)
	if !AboutAgents(a) || !LoadConfig(t.ConfigPath).AutoContain {
		return err
	}
	if _, locked := ReadMarker(t.MarkerPath); locked {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.last) < 10*time.Minute {
		return err
	}
	t.last = time.Now()
	b, _ := json.Marshal(Request{Time: time.Now().UTC(), Reason: a.Summary, Auto: true})
	tmp := t.RequestPath + ".tmp"
	if werr := os.WriteFile(tmp, b, 0o644); werr == nil {
		_ = os.Rename(tmp, t.RequestPath)
	}
	return err
}
