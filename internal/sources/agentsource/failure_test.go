package agentsource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func agentDir(t *testing.T) (root, dir string) {
	t.Helper()
	root = t.TempDir()
	dir = filepath.Join(root, "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, dir
}

func writeRaw(t *testing.T, path, body string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestMissingDirectoryIsReportedNotSilentlyClean(t *testing.T) {
	w := NewWatcher(filepath.Join(t.TempDir(), "nope"))
	events, err := w.Poll()
	var issue Issue
	if len(events) != 0 || !errors.As(err, &issue) || issue.Code != CodeUnreadable || issue.Remedy == "" {
		t.Fatalf("events=%v err=%v", events, err)
	}
}

func TestDirectoryThatAppearsLaterIsPickedUp(t *testing.T) {
	root := filepath.Join(t.TempDir(), "later")
	w := NewWatcher(root)
	if _, err := w.Poll(); err == nil {
		t.Fatal("want an error while the directory is missing")
	}
	if err := os.MkdirAll(filepath.Join(root, "agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeAgentSession(t, root, "s1", []map[string]any{{"role": "user", "content": "hi"}})
	events, err := w.Poll()
	if err != nil || len(events) == 0 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
}

func TestUnreadableFileIsReportedOnceAndOthersStillRead(t *testing.T) {
	root, dir := agentDir(t)
	// A directory named like a session file cannot be read as a file on any OS.
	if err := os.Mkdir(filepath.Join(dir, "locked.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeAgentSession(t, root, "good", []map[string]any{{"role": "user", "content": "hello"}})
	w := NewWatcher(root)
	events, err := w.Poll()
	if err != nil || len(events) == 0 {
		t.Fatalf("a bad file must not stop the good one: events=%d err=%v", len(events), err)
	}
	issues := w.Issues()
	if len(issues) != 1 || issues[0].Code != CodeUnreadable || !strings.Contains(issues[0].Path, "locked.json") {
		t.Fatalf("%+v", issues)
	}
	// Polling again must not repeat the same report.
	w.Poll()
	if again := w.Issues(); len(again) != 0 {
		t.Fatalf("repeated: %+v", again)
	}
}

func TestPartialWriteIsRetriedSilentlyButDamageIsReported(t *testing.T) {
	root, dir := agentDir(t)
	path := filepath.Join(dir, "s1.json")
	writeRaw(t, path, `{"session_id":"s1","messages":[{"role":"user","con`, 0) // being written right now
	w := NewWatcher(root)
	if events, _ := w.Poll(); len(events) != 0 || len(w.Issues()) != 0 {
		t.Fatal("an in-progress write is not damage")
	}
	// The writer finishes: the same file is picked up on the next poll.
	writeRaw(t, path, `{"session_id":"s1","messages":[{"role":"user","content":"done"}]}`, 0)
	events, _ := w.Poll()
	if len(events) != 2 { // session_created + the message
		t.Fatalf("complete file not read after retry: %d events", len(events))
	}

	// A file that stays invalid after settling is damage.
	writeRaw(t, filepath.Join(dir, "bad.json"), `{"session_id":`, time.Hour)
	writeRaw(t, filepath.Join(dir, "empty.json"), ``, time.Hour)
	w.Poll()
	issues := w.Issues()
	if len(issues) != 2 {
		t.Fatalf("want 2 malformed reports, got %+v", issues)
	}
	for _, i := range issues {
		if i.Code != CodeMalformed {
			t.Errorf("%+v", i)
		}
	}
}

func TestUnknownMessageShapeIsReportedAndRestStillScanned(t *testing.T) {
	root, dir := agentDir(t)
	writeRaw(t, filepath.Join(dir, "s1.json"),
		`{"session_id":"s1","messages":[42,{"role":"user","content":[{"type":"text","text":"parts"}]},{"role":"user","content":"plain"}]}`, time.Hour)
	w := NewWatcher(root)
	events, err := w.Poll()
	if err != nil {
		t.Fatal(err)
	}
	var plain bool
	for _, e := range events {
		plain = plain || e.Text == "plain"
	}
	if !plain {
		t.Fatal("a message Heimdall cannot decode must not hide the ones it can")
	}
	issues := w.Issues()
	if len(issues) != 1 || issues[0].Code != CodeUnknownShape {
		t.Fatalf("%+v", issues)
	}
}

func TestSystemAndEmptyMessagesAreNotShapeProblems(t *testing.T) {
	root, _ := agentDir(t)
	writeAgentSession(t, root, "s1", []map[string]any{{"role": "system", "content": "x"}, {"role": "tool", "content": ""}})
	w := NewWatcher(root)
	w.Poll()
	if i := w.Issues(); len(i) != 0 {
		t.Fatalf("%+v", i)
	}
}

func TestRunReportsIssuesOnceAndKeepsGoing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	w := NewWatcher(missing)
	ctx, cancel := context.WithCancel(context.Background())
	var got []error
	done := make(chan struct{})
	go func() {
		w.Run(ctx, 5*time.Millisecond, func(err error) { got = append(got, err) }, nil)
		close(done)
	}()
	time.Sleep(80 * time.Millisecond) // many polls, one persistent problem
	cancel()
	<-done
	if len(got) != 1 {
		t.Fatalf("a persistent problem should be reported once, got %d", len(got))
	}
}
