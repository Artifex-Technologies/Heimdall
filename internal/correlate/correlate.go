// Package correlate links related alerts into incidents (Phase 5, the transferable half of microsoft/graphrag: a graph built
// from the entities records share, not its LLM retrieval). Each alert names things: an agent session, a Limbo guest, a remote
// address, a file, a program, a remote-access tool. Alerts that share any of them within Window are one incident; when an
// incident holds alerts from two or more detectors, one "incident" alert says so, with the detectors and the shared things.
// A prompt injection and a new connection from the same session, a tunnel interface and the program behind it, a guest
// started without a firewall and its rejected image: each alone may be noise, together they are a story.
//
// It is a sink wrapper: work happens only when an alert is written, nothing runs in between. Memory is bounded (incidents
// expire after Window; at most maxIncidents, keys and members per incident capped).
package correlate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

const (
	DetectorID   = "incident"
	maxIncidents = 200
	maxMembers   = 50
	maxKeys      = 64
)

// keyFields are the alert fields that name a thing worth linking on, and the kind each names.
var keyFields = map[string]string{
	"guest": "guest", "remote_addr": "address", "src": "address", "other_ip": "address", "path": "file",
	"provider": "tool", "pid": "process", "process": "program", "app": "app", "request_id": "request",
}

// skip are detectors whose alerts are about Heimdall itself or are already summaries.
var skip = map[string]bool{DetectorID: true, "integration": true, "maintenance-window": true, "baseline-drift": true, "resource-pressure": true}

// Incident is a group of related alerts.
type Incident struct {
	ID        string         `json:"id"`
	First     time.Time      `json:"first"`
	Last      time.Time      `json:"last"`
	Severity  string         `json:"severity"`
	Detectors map[string]int `json:"detectors"`
	Keys      []string       `json:"keys"`
	Alerts    []Member       `json:"alerts"`

	keys     map[string]bool
	reported int // number of detectors when last reported
}

// Member is one alert of an incident, briefly.
type Member struct {
	Time       time.Time `json:"time"`
	DetectorID string    `json:"detector_id"`
	Severity   string    `json:"severity"`
	Summary    string    `json:"summary"`
}

// Correlator passes every alert on to Next, then links it.
type Correlator struct {
	Next   alert.Sink
	Window time.Duration // default 30 minutes
	Now    func() time.Time

	mu        sync.Mutex
	incidents []*Incident
	seq       int
}

// Keys returns the things an alert names, as "kind:value".
func Keys(a alert.Alert) []string {
	var ks []string
	if a.SessionID != "" {
		ks = append(ks, "session:"+a.SessionID)
	}
	for f, kind := range keyFields {
		v := a.Fields[f]
		if v == "" || v == "unknown" || v == "0" || (f == "pid" && v == "-1") {
			continue
		}
		ks = append(ks, kind+":"+v)
	}
	sort.Strings(ks)
	return ks
}

func rank(s string) int {
	switch s {
	case string(detect.SeverityCritical):
		return 2
	case string(detect.SeverityWarning):
		return 1
	}
	return 0
}

func (c *Correlator) Write(a alert.Alert) error {
	err := c.Next.Write(a)
	if skip[a.DetectorID] {
		return err
	}
	keys := Keys(a)
	if len(keys) == 0 {
		return err
	}
	if inc := c.link(a, keys); inc != nil {
		_ = c.Next.Write(c.alertFor(inc))
	}
	return err
}

// link adds the alert to the incident(s) it shares a key with (merging them), and returns the incident when it now spans a
// new number of detectors (two or more) and holds at least one warning: then it is reported (again).
func (c *Correlator) link(a alert.Alert, keys []string) *Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	window := c.Window
	if window <= 0 {
		window = 30 * time.Minute
	}
	live := c.incidents[:0]
	for _, inc := range c.incidents {
		if now.Sub(inc.Last) <= window {
			live = append(live, inc)
		}
	}
	c.incidents = live

	var into *Incident
	kept := c.incidents[:0]
	for _, inc := range c.incidents {
		shared := false
		for _, k := range keys {
			if inc.keys[k] {
				shared = true
				break
			}
		}
		switch {
		case !shared:
			kept = append(kept, inc)
		case into == nil:
			into = inc
			kept = append(kept, inc)
		default: // a second incident shares a key: they are one story
			merge(into, inc)
		}
	}
	c.incidents = kept
	if into == nil {
		c.seq++
		into = &Incident{ID: "inc-" + strconv.Itoa(c.seq), First: now, Detectors: map[string]int{}, keys: map[string]bool{}}
		c.incidents = append(c.incidents, into)
		if len(c.incidents) > maxIncidents {
			c.incidents = c.incidents[1:]
		}
	}
	into.Last = now
	for _, k := range keys {
		if len(into.keys) < maxKeys {
			into.keys[k] = true
		}
	}
	into.Detectors[a.DetectorID]++
	if rank(string(a.Severity)) > rank(into.Severity) || into.Severity == "" {
		into.Severity = string(a.Severity)
	}
	into.Alerts = append(into.Alerts, Member{a.Time, a.DetectorID, string(a.Severity), a.Summary})
	if len(into.Alerts) > maxMembers {
		into.Alerts = into.Alerts[len(into.Alerts)-maxMembers:]
	}
	if len(into.Detectors) >= 2 && len(into.Detectors) > into.reported && rank(into.Severity) >= 1 {
		into.reported = len(into.Detectors)
		cp := *into
		cp.Keys = sortedKeys(into.keys)
		return &cp
	}
	return nil
}

func merge(into, from *Incident) {
	if from.First.Before(into.First) {
		into.First = from.First
	}
	for k := range from.keys {
		if len(into.keys) < maxKeys {
			into.keys[k] = true
		}
	}
	for d, n := range from.Detectors {
		into.Detectors[d] += n
	}
	if rank(from.Severity) > rank(into.Severity) {
		into.Severity = from.Severity
	}
	into.Alerts = append(from.Alerts, into.Alerts...)
	sort.Slice(into.Alerts, func(i, j int) bool { return into.Alerts[i].Time.Before(into.Alerts[j].Time) })
	if len(into.Alerts) > maxMembers {
		into.Alerts = into.Alerts[len(into.Alerts)-maxMembers:]
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c *Correlator) alertFor(inc *Incident) alert.Alert {
	dets := make([]string, 0, len(inc.Detectors))
	for d := range inc.Detectors {
		dets = append(dets, d)
	}
	sort.Strings(dets)
	keys := inc.Keys
	if len(keys) > 6 {
		keys = append(keys[:6:6], fmt.Sprintf("and %d more", len(inc.Keys)-6))
	}
	n := 0
	for _, v := range inc.Detectors {
		n += v
	}
	summary := fmt.Sprintf("%d related alerts from %d detectors (%s) share %s", n, len(dets), strings.Join(dets, ", "), strings.Join(keys, ", "))
	return alert.FromFinding(detect.Finding{DetectorID: DetectorID, Severity: detect.Severity(inc.Severity), Summary: summary,
		Event: detect.Event{Source: "correlation", Kind: "incident", Time: inc.Last,
			Fields: map[string]string{"incident_id": inc.ID, "detectors": strings.Join(dets, ","), "keys": strings.Join(inc.Keys, ",")}}})
}

// Incidents returns the live incidents, newest first (for GET /v1/incidents).
func (c *Correlator) Incidents() []Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Incident, 0, len(c.incidents))
	for i := len(c.incidents) - 1; i >= 0; i-- {
		cp := *c.incidents[i]
		cp.Keys = sortedKeys(cp.keys)
		cp.Detectors = map[string]int{}
		for k, v := range c.incidents[i].Detectors {
			cp.Detectors[k] = v
		}
		cp.Alerts = append([]Member(nil), c.incidents[i].Alerts...)
		out = append(out, cp)
	}
	return out
}
