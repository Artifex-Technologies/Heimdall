package maintenance

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOpenCapsAndRequiresReason(t *testing.T) {
	now := time.Now()
	w, err := Open("claude-agent", "updates", 10*time.Hour, now)
	if err != nil || w.Until.Sub(now) != MaxDuration {
		t.Fatalf("cap: %v %+v", err, w)
	}
	if _, err := Open("x", "", time.Hour, now); err == nil {
		t.Fatal("a reason is required")
	}
	if _, err := Open("x", "r", 0, now); err == nil {
		t.Fatal("a duration is required")
	}
}

func TestWriteReadExpire(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	now := time.Now()
	w, _ := Open("zlothra", "kernel update", time.Hour, now)
	if err := Write(p, w); err != nil {
		t.Fatal(err)
	}
	m := NewWatcher(p)
	if got, ok := m.Active(); !ok || got.Reason != "kernel update" {
		t.Fatalf("should be open: %+v %v", got, ok)
	}
	m.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, ok := m.Active(); ok {
		t.Fatal("must close by itself")
	}
	if err := Clear(p); err != nil {
		t.Fatal(err)
	}
	if _, found := Read(p); found {
		t.Fatal("cleared")
	}
}

func TestHandEditedFileIsCapped(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	now := time.Now()
	Write(p, Window{Reason: "x", Actor: "a", Opened: now, Until: now.Add(48 * time.Hour)})
	w, _ := Read(p)
	if w.Until.Sub(w.Opened) != MaxDuration {
		t.Fatalf("not capped: %v", w.Until.Sub(w.Opened))
	}
}
