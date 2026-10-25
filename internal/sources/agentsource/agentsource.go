// Package agentsource turns Sarina's on-disk session files into
// detect.Events. Sarina persists one JSON file per session under its
// workspace's .port_sessions/ directory; this package polls that directory
// rather than importing Sarina, since the two are separate processes and
// this file format is the boundary between them.
//
// Two shapes are read. The current one is the agent's own session file,
// .port_sessions/agent/<id>.json, whose "messages" are objects (role,
// content, optional tool_calls); this is the contract with Sarina's Go
// core. The older flat shape ("messages" as plain strings, directly under
// .port_sessions/) is still accepted so existing fixtures and old files keep
// working.
//
// Polling, not fsnotify: a single operator's session directory sees at most
// a few writes a minute, and stdlib os.Stat is one syscall per file per
// poll -- not worth a dependency for this scale. Revisit if a future phase
// needs to watch thousands of files (host-wide FIM).
package agentsource

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// sessionFile is the part of a Sarina session file this package needs.
// Messages stay raw because they are plain strings in the old shape and
// objects in the current one.
type sessionFile struct {
	SessionID string            `json:"session_id"`
	Messages  []json.RawMessage `json:"messages"`
}

// messageObject is one transcript entry of the agent session file.
type messageObject struct {
	Role      string `json:"role"`
	Content   string `json:"content"`
	Name      string `json:"name"`
	ToolCalls []struct {
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

// decodeMessage returns the role (empty for the old string shape) and the
// text worth scanning. System messages and empty entries yield ok=false: the
// system prompt is the agent's own instruction text, not content to watch, and
// scanning it would only produce false positives. For an assistant message the
// text includes the tool calls it issued, since those are where a command or
// a credential would show up.
func decodeMessage(raw json.RawMessage) (role, text string, ok bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return "", s, true
	}
	var m messageObject
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", false
	}
	if m.Role == "system" {
		return m.Role, "", false
	}
	text = m.Content
	for _, tc := range m.ToolCalls {
		if text != "" {
			text += "\n"
		}
		text += tc.Function.Name + " " + tc.Function.Arguments
	}
	if text == "" {
		return m.Role, "", false
	}
	if m.Role == "tool" {
		text = unwrapJSON(text)
	}
	return m.Role, text, true
}

// unwrapJSON turns a tool result Sarina stored as JSON ({"tool": "read_file", "content": "line one\nline two"}) into the text it
// carries: every string value, decoded, one after another. Scanned as stored, a file's line breaks are the two characters "\n", so a
// planted line ("\nSYSTEM NOTICE TO THE ASSISTANT: ...") starts mid-word and the detectors' word boundaries never match (found by
// Sarina's injection evals, 2026-10-25). Text that is not JSON is returned as it is.
func unwrapJSON(text string) string {
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return text
	}
	var parts []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if t != "" {
				parts = append(parts, t)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		}
	}
	walk(v)
	if len(parts) == 0 {
		return text
	}
	return strings.Join(parts, "\n")
}

// readable reports whether raw is a message shape this package understands (a
// plain string or an object). decodeMessage also returns ok=false for a
// readable-but-empty message, which is not a problem; an unreadable one is.
func readable(raw json.RawMessage) bool {
	var s string
	var m messageObject
	return json.Unmarshal(raw, &s) == nil || json.Unmarshal(raw, &m) == nil
}

// Stable codes for problems reading Sarina's session files; see
// docs/INTEGRATION-FAILURES.md.
const (
	CodeUnreadable   = "agent_session_unreadable"    // directory or file cannot be read
	CodeMalformed    = "agent_session_malformed"     // file is not valid JSON and is not being written
	CodeUnknownShape = "agent_session_unknown_shape" // messages Heimdall cannot decode, so cannot scan

	// settleTime is how long a file must be unmodified before invalid JSON in it
	// counts as damage rather than a write in progress.
	settleTime = 5 * time.Second
)

// Issue is a problem reading the session files. Detection of everything that
// could be read carries on; the issue is how the blind spot gets reported.
type Issue struct {
	Code   string
	Path   string
	Detail string
	Remedy string
}

func (i Issue) Error() string {
	return i.Code + ": " + i.Path + ": " + i.Detail + " (remedy: " + i.Remedy + ")"
}

type fileState struct {
	modTime      time.Time
	messageCount int
}

// savedState is fileState on disk.
type savedState struct {
	ModTime  time.Time `json:"mod_time"`
	Messages int       `json:"messages"`
}

// Watcher polls one directory of Sarina session files.
type Watcher struct {
	dir      string
	seen     map[string]fileState
	issues   []Issue
	reported map[string]bool // code|path|modtime already reported, to avoid repeating every poll
	// statePath keeps how far each session was read, so a restart goes on from there instead of reading (and alerting on)
	// every old session again. Empty: kept in memory only (a one-off scan).
	statePath string
	saved     string
	baseline  bool // the next poll only records where the sessions are (no events)
}

func NewWatcher(dir string) *Watcher {
	return &Watcher{dir: dir, seen: make(map[string]fileState), reported: make(map[string]bool)}
}

// NewWatcherWithState is NewWatcher that remembers, across restarts, how far each session was read (in statePath).
func NewWatcherWithState(dir, statePath string) *Watcher {
	w := NewWatcher(dir)
	w.statePath = statePath
	var st map[string]savedState
	if b, err := os.ReadFile(statePath); err == nil && json.Unmarshal(b, &st) == nil {
		for k, v := range st {
			w.seen[k] = fileState{modTime: v.ModTime, messageCount: v.Messages}
		}
		w.saved = string(b)
	} else if os.IsNotExist(err) {
		// no position kept yet (this version's first start): the sessions already there were read by the Heimdall that ran
		// before, so reading starts after them instead of alerting on all of them again. A new install has none.
		w.baseline = true
	}
	return w
}

func (w *Watcher) saveState() {
	if w.statePath == "" {
		return
	}
	st := make(map[string]savedState, len(w.seen))
	for k, v := range w.seen {
		st[k] = savedState{ModTime: v.modTime, Messages: v.messageCount}
	}
	b, err := json.Marshal(st)
	if err != nil || string(b) == w.saved {
		return
	}
	tmp := w.statePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, w.statePath) == nil {
		w.saved = string(b)
	}
}

// Issues returns, and clears, the per-file problems found by the last Poll.
// Each distinct problem is returned once per file version.
func (w *Watcher) Issues() []Issue {
	out := w.issues
	w.issues = nil
	return out
}

func (w *Watcher) report(i Issue, mod time.Time) {
	key := i.Code + "|" + i.Path + "|" + mod.String()
	if w.reported[key] {
		return
	}
	w.reported[key] = true
	w.issues = append(w.issues, i)
}

// Poll scans the directory once and returns Events for anything new since
// the last call: a session_created Event for a file seen for the first
// time, and a message Event for each message beyond what was already
// processed (covering both a brand-new file and one that grew).
func (w *Watcher) Poll() ([]detect.Event, error) {
	// A missing or unreadable directory would otherwise look exactly like "no
	// sessions, nothing wrong", because Glob reports neither.
	if _, err := os.Stat(w.dir); err != nil {
		return nil, Issue{CodeUnreadable, w.dir, err.Error(), "check agent_session_dir points at Sarina's .port_sessions and that heimdalld's user can read it (ls -ld " + w.dir + ")"}
	}
	matches, err := filepath.Glob(filepath.Join(w.dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("agentsource: glob %s: %w", w.dir, err)
	}
	// The agent's own session files live one level down.
	agentMatches, err := filepath.Glob(filepath.Join(w.dir, "agent", "*.json"))
	if err != nil {
		return nil, fmt.Errorf("agentsource: glob %s: %w", w.dir, err)
	}
	matches = append(matches, agentMatches...)

	var events []detect.Event
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			continue // file removed between Glob and Stat; skip this cycle
		}
		name := filepath.Base(path)
		key := path // the same file name can exist in both locations
		prior, known := w.seen[key]
		if known && !info.ModTime().After(prior.modTime) {
			continue // unchanged since last poll
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			w.report(Issue{CodeUnreadable, path, err.Error(), "make the file readable by heimdalld's user (ls -l " + path + ")"}, info.ModTime())
			continue // retry next poll
		}
		var sf sessionFile
		if err := json.Unmarshal(raw, &sf); err != nil {
			// Possibly a write in progress: only a file that has stopped changing
			// is reported, and either way it is retried next poll.
			if time.Since(info.ModTime()) > settleTime {
				w.report(Issue{CodeMalformed, path, err.Error(), "the session file is damaged or not Sarina's format; its contents are NOT being scanned"}, info.ModTime())
			}
			continue
		}
		sessionID := sf.SessionID
		if sessionID == "" {
			sessionID = name
		}

		if !known {
			events = append(events, detect.Event{
				Source:    "agent-session",
				SessionID: sessionID,
				Time:      info.ModTime(),
				Kind:      "session_created",
				Text:      "",
				Fields:    map[string]string{"file": name},
			})
		}

		startAt := 0
		if known {
			startAt = prior.messageCount
		}
		for i := startAt; i < len(sf.Messages); i++ {
			role, text, ok := decodeMessage(sf.Messages[i])
			if !ok {
				if !readable(sf.Messages[i]) {
					w.report(Issue{CodeUnknownShape, path, fmt.Sprintf("message %d has a shape Heimdall cannot decode", i), "Sarina's session format may have changed; check docs/spec/01-agent-core.md section 4.2 against agentsource"}, info.ModTime())
				}
				continue
			}
			fields := map[string]string{"file": name}
			if role != "" {
				fields["role"] = role
			}
			events = append(events, detect.Event{
				Source:    "agent-session",
				SessionID: sessionID,
				Time:      info.ModTime(),
				Kind:      "message",
				Text:      text,
				Fields:    fields,
			})
		}

		w.seen[key] = fileState{modTime: info.ModTime(), messageCount: len(sf.Messages)}
	}
	if w.baseline {
		w.baseline = false
		events = nil
	}
	w.saveState()
	return events, nil
}

// Run polls on an interval until ctx is done, delivering every Event from
// each cycle to emit in order. Poll errors (e.g. the directory not existing
// yet) are non-fatal -- Heimdall should keep trying rather than exit, since
// the directory may simply not have been created until Sarina's first run.
func (w *Watcher) Run(ctx context.Context, interval time.Duration, onErr func(error), emit func(detect.Event)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastErr := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := w.Poll()
			// A persistent directory problem is reported once, not every poll.
			if err != nil && err.Error() != lastErr && onErr != nil {
				onErr(err)
			}
			lastErr = ""
			if err != nil {
				lastErr = err.Error()
			}
			for _, i := range w.Issues() {
				if onErr != nil {
					onErr(i)
				}
			}
			for _, e := range events {
				emit(e)
			}
		}
	}
}
