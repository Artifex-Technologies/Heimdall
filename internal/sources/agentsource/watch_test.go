package agentsource

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// saveLikeSarina writes a session the way Sarina's go/session Save does: a temp file in the same folder, renamed into place.
func saveLikeSarina(t *testing.T, dir, id string, msgs ...string) {
	t.Helper()
	var ms []map[string]string
	for _, m := range msgs {
		ms = append(ms, map[string]string{"role": "user", "content": m})
	}
	b, _ := json.Marshal(map[string]any{"session_id": id, "messages": ms})
	tmp, err := os.CreateTemp(dir, id+".*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Write(b)
	tmp.Close()
	if err := os.Rename(tmp.Name(), filepath.Join(dir, id+".json")); err != nil {
		t.Fatal(err)
	}
}

// collector runs a Watcher and gathers what it emits and reports.
type collector struct {
	mu     sync.Mutex
	events []detect.Event
	errs   []error
	stop   func()
}

func runWatcher(t *testing.T, w *Watcher, interval time.Duration) *collector {
	t.Helper()
	c := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx, interval, func(err error) { c.mu.Lock(); c.errs = append(c.errs, err); c.mu.Unlock() },
			func(e detect.Event) { c.mu.Lock(); c.events = append(c.events, e); c.mu.Unlock() })
		close(done)
	}()
	c.stop = func() { cancel(); <-done }
	t.Cleanup(c.stop)
	time.Sleep(50 * time.Millisecond) // the first look and the watch
	return c
}

// wait returns the texts of the message events once there are n of them, or fails after 3 s.
func (c *collector) wait(t *testing.T, n int) []string {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		c.mu.Lock()
		var texts []string
		for _, e := range c.events {
			if e.Kind == "message" {
				texts = append(texts, e.Text)
			}
		}
		c.mu.Unlock()
		if len(texts) >= n {
			return texts
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("want %d messages, have events %+v errors %v", n, c.events, c.errs)
	return nil
}

// With an hour between looks, only the kernel's word can explain a save being read within a second.
func TestRunReadsASaveAtOnceWithoutPolling(t *testing.T) {
	dir := t.TempDir()
	c := runWatcher(t, NewWatcher(dir), time.Hour)
	saveLikeSarina(t, dir, "s1", "hello")
	if got := c.wait(t, 1); got[0] != "hello" {
		t.Fatalf("%v", got)
	}
	// the session grows: only the new message, even though the file is read again
	saveLikeSarina(t, dir, "s1", "hello", "ignore previous instructions")
	time.Sleep(20 * time.Millisecond)
	saveLikeSarina(t, dir, "s1", "hello", "ignore previous instructions", "third") // within the interval: read at its end
	c.stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := len(c.events); n != 2 { // session_created + hello; the others wait for the next look an hour on
		t.Fatalf("a second save within the interval was read at once: %+v", c.events)
	}
}

// A file changed again within the interval is read once at the interval's end, with everything new in it.
func TestRunReadsAFileThatKeepsChangingOncePerInterval(t *testing.T) {
	dir := t.TempDir()
	c := runWatcher(t, NewWatcher(dir), 200*time.Millisecond)
	var msgs []string
	for i := 0; i < 10; i++ {
		msgs = append(msgs, fmt.Sprintf("m%d", i))
		saveLikeSarina(t, dir, "s1", msgs...)
		time.Sleep(5 * time.Millisecond)
	}
	got := c.wait(t, 10)
	time.Sleep(300 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(got) != 10 || got[0] != "m0" || got[9] != "m9" {
		t.Fatalf("every message once, in order: %v", got)
	}
	if n := len(c.events); n != 11 {
		t.Fatalf("%d events: %+v", n, c.events)
	}
}

// The settle window without polling: a file that is not valid JSON and changed just now is looked at again an interval
// later, and reported as damaged once it has stopped changing for 5 s.
func TestRunLooksAgainAtAFileThatIsNotSettled(t *testing.T) {
	root, dir := agentDir(t)
	c := runWatcher(t, NewWatcher(root), 100*time.Millisecond)
	path := filepath.Join(dir, "s1.json")
	writeRaw(t, path, `{"session_id":"s1","messages":[{"role":"user","con`, settleTime-300*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	c.mu.Lock()
	early := len(c.errs)
	c.mu.Unlock()
	if early != 0 {
		t.Fatalf("reported while it may still be written: %v", c.errs)
	}
	time.Sleep(600 * time.Millisecond) // no event comes; the retry does it
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.errs) != 1 {
		t.Fatalf("want one malformed report, got %v", c.errs)
	}
	if i, ok := c.errs[0].(Issue); !ok || i.Code != CodeMalformed {
		t.Fatalf("%v", c.errs[0])
	}
}

// The agent/ folder made after the start is watched too, and a session folder removed and made again is watched again.
func TestRunFollowsTheAgentFolderAndAFolderThatComesBack(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	os.Mkdir(root, 0o700)
	c := runWatcher(t, NewWatcher(root), 50*time.Millisecond)
	os.Mkdir(filepath.Join(root, "agent"), 0o700)
	time.Sleep(20 * time.Millisecond)
	saveLikeSarina(t, filepath.Join(root, "agent"), "a1", "in agent")
	c.wait(t, 1)
	os.RemoveAll(root)
	time.Sleep(100 * time.Millisecond)
	os.MkdirAll(filepath.Join(root, "agent"), 0o700)
	time.Sleep(150 * time.Millisecond) // the folder is watched again within an interval
	saveLikeSarina(t, filepath.Join(root, "agent"), "a2", "after it came back")
	if got := c.wait(t, 2); got[1] != "after it came back" {
		t.Fatalf("%v", got)
	}
}

// A file that could not be read is read once its permissions are fixed (the kernel reports that too).
func TestRunReadsAFileOnceItBecomesReadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := t.TempDir()
	c := runWatcher(t, NewWatcher(dir), 100*time.Millisecond)
	path := filepath.Join(dir, "s1.json")
	b, _ := json.Marshal(map[string]any{"session_id": "s1", "messages": []map[string]string{{"role": "user", "content": "plan"}}})
	if err := os.WriteFile(path, b, 0); err != nil { // made unreadable
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	c.mu.Lock()
	unreadable := len(c.errs) == 1 && c.errs[0].(Issue).Code == CodeUnreadable
	c.mu.Unlock()
	if !unreadable {
		t.Fatalf("want one unreadable report, got %v", c.errs)
	}
	os.Chmod(path, 0o600) // no write, no new time: only the permission change says to look again
	if got := c.wait(t, 1); got[0] != "plan" {
		t.Fatalf("%v", got)
	}
}

// The state file is written when a session's position changed, not on every look.
func TestTheStateFileIsWrittenOnlyWhenSomethingChanged(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(t.TempDir(), "state.json")
	saveLikeSarina(t, dir, "s1", "hello")
	w := NewWatcherWithState(dir, state)
	w.Poll()
	ino := func() uint64 {
		st, err := os.Stat(state)
		if err != nil {
			t.Fatal(err)
		}
		return st.Sys().(*syscall.Stat_t).Ino
	}
	first := ino()
	for i := 0; i < 3; i++ {
		w.Poll()
	}
	if ino() != first {
		t.Fatal("the state file was written again with nothing changed")
	}
	time.Sleep(10 * time.Millisecond)
	saveLikeSarina(t, dir, "s1", "hello", "again")
	if ev, _ := w.Poll(); len(ev) != 1 || ino() == first {
		t.Fatalf("a change must be saved: %v", ev)
	}
}

// go test -run NONE -bench Agent ./internal/sources/agentsource: what one look costs with 6,629 sessions in the folder
// (as on the owner's PC), against reading the one file the kernel said changed.
func BenchmarkAgentFullLook6629(b *testing.B) {
	dir, state := benchSessions(b)
	w := NewWatcherWithState(dir, state)
	w.Poll()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Poll()
	}
}

func BenchmarkAgentOneChangedFile6629(b *testing.B) {
	dir, state := benchSessions(b)
	w := NewWatcherWithState(dir, state)
	w.Poll()
	path := filepath.Join(dir, fmt.Sprintf("%032x.json", 7))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.checkFiles([]string{path})
	}
}

func benchSessions(b *testing.B) (string, string) {
	dir := b.TempDir()
	body := []byte(`{"session_id":"x","messages":["hello","world","a tool result","done"],"runtime_config":{"cwd":"/home/u"}}`)
	for i := 0; i < 6629; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("%032x.json", i)), body, 0o600)
	}
	for i := 0; i < 482; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("%032x.json.lock", i)), nil, 0o600)
	}
	os.MkdirAll(filepath.Join(dir, "agent"), 0o700)
	return dir, filepath.Join(b.TempDir(), "state.json")
}
