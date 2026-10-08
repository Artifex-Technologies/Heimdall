// Package limbosource tails Limbo's audit log (events.jsonl) into Events.
//
// Limbo is the ecosystem's guest-application sandbox; its log is the contract
// described in Limbo's docs/EVENTS.md. Like agentsource, this reads another
// project's on-disk output from outside its process: no shared code, no
// writes, and a format change on Limbo's side is absorbed here.
//
// Two properties matter more than they look:
//
//   - Only complete lines are consumed. Limbo appends and syncs one line per
//     event, but a poll can land between the write of a line's bytes and its
//     newline; consuming the partial line would both mis-parse it and skip it
//     forever once the offset moved past it.
//   - The read offset can be persisted. Without it a restart either replays the
//     whole history (re-alerting on old events) or starts at the end (missing
//     whatever happened while Heimdall was down). Resume-from-offset is the only
//     way to be correct across restarts, so a state path is supported; with none
//     configured a `run` starts at the end, and `scan` (an audit) reads it all.
package limbosource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Source is the value stamped on every Event this package produces; the
// limbo-guest detector keys on it.
const Source = "limbo"

// maxLine bounds how much of a single line is parsed. Limbo's events are tiny;
// a megabyte-long line means something else is writing to the file.
const maxLine = 1 << 20

// record mirrors one line of Limbo's log. Detail is strings only by contract.
type record struct {
	Time   time.Time         `json:"time"`
	Kind   string            `json:"kind"`
	Guest  string            `json:"guest"`
	Detail map[string]string `json:"detail"`
}

// Watcher polls the log from a remembered offset.
type Watcher struct {
	path      string
	statePath string
	offset    int64
	started   bool
	fromStart bool
	// Skipped counts lines that were not valid records. A rising count means
	// the contract drifted or something foreign is writing to the file.
	Skipped int
}

// NewWatcher watches path. If statePath is set and readable, polling resumes
// from the saved offset. Otherwise it starts at the end of the file, unless
// fromStart is true (use for one-shot scans).
func NewWatcher(path, statePath string, fromStart bool) *Watcher {
	w := &Watcher{path: path, statePath: statePath, fromStart: fromStart}
	if statePath != "" {
		if b, err := os.ReadFile(statePath); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n >= 0 {
				w.offset, w.started = n, true
			}
		}
	}
	return w
}

// Poll returns Events for every complete line appended since the last call.
// A missing file is not an error (Limbo may simply not have run yet).
func (w *Watcher) Poll() ([]detect.Event, error) {
	f, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !w.started {
		w.started = true
		if !w.fromStart {
			w.offset = fi.Size()
			return nil, w.save()
		}
	}
	if fi.Size() < w.offset {
		// Truncated or replaced by a smaller file: the old offset is
		// meaningless. Start over rather than skip whatever the new file holds.
		w.offset = 0
	}
	if fi.Size() == w.offset {
		return nil, nil
	}

	if _, err := f.Seek(w.offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(io.LimitReader(f, fi.Size()-w.offset))
	if err != nil {
		return nil, err
	}
	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		return nil, nil // only a partial line so far
	}

	var events []detect.Event
	for _, line := range bytes.Split(buf[:end], []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		ev, ok := parseLine(line)
		if !ok {
			w.Skipped++
			continue
		}
		events = append(events, ev)
	}
	w.offset += int64(end) + 1
	return events, w.save()
}

func parseLine(line []byte) (detect.Event, bool) {
	if len(line) > maxLine {
		return detect.Event{}, false
	}
	var r record
	if err := json.Unmarshal(line, &r); err != nil || r.Kind == "" || r.Guest == "" {
		return detect.Event{}, false
	}
	fields := make(map[string]string, len(r.Detail)+1)
	for k, v := range r.Detail {
		fields[k] = v
	}
	fields["guest"] = r.Guest // set last so a detail key can never spoof it
	return detect.Event{
		Source: Source,
		Time:   r.Time,
		Kind:   r.Kind,
		Text:   summarize(r),
		Fields: fields,
	}, true
}

// summarize renders a stable one-line description. Keys are sorted so the same
// record always yields the same text.
func summarize(r record) string {
	keys := make([]string, 0, len(r.Detail))
	for k := range r.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "limbo %s guest=%s", r.Kind, r.Guest)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%s", k, r.Detail[k])
	}
	return b.String()
}

// save persists the offset atomically (write temp, rename), the same way the
// FIM baseline is saved, so a crash mid-write cannot leave a corrupt offset.
func (w *Watcher) save() error {
	if w.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(w.statePath), 0o700); err != nil {
		return err
	}
	tmp := w.statePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(w.offset, 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.statePath)
}

// Run polls on an interval until ctx is done. Poll errors are reported through
// onErr and polling continues; the log appearing later is normal.
func (w *Watcher) Run(ctx context.Context, interval time.Duration, onErr func(error), emit func(detect.Event)) {
	tick := func() {
		events, err := w.Poll()
		if err != nil && onErr != nil {
			onErr(err)
		}
		for _, e := range events {
			emit(e)
		}
	}
	tick()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
