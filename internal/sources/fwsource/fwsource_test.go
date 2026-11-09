package fwsource

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

var n int

func line(ident, msg string) string {
	n++
	b, _ := json.Marshal(map[string]string{"MESSAGE": msg, "SYSLOG_IDENTIFIER": ident, "__REALTIME_TIMESTAMP": "1761170000000000", "__CURSOR": "s=abc;i=" + string(rune('0'+n))})
	return string(b)
}

// fakeJournal is a stand-in journalctl. Start k prints out[k] (if any), then follows forever when stay[k], or ends with
// err[k] on stderr and exit status 1. Every start's arguments are kept, one line each.
type fakeJournal struct {
	dir string
}

func newFakeJournal(t *testing.T) (*fakeJournal, *Watcher) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
d=%s
echo "$*" >> $d/args
n=$(cat $d/n 2>/dev/null || echo 0); n=$((n+1)); echo $n > $d/n
[ -f $d/out$n ] && cat $d/out$n
[ -f $d/stay$n ] && exec sleep 1000
[ -f $d/err$n ] && { cat $d/err$n >&2; exit 1; }
exit 0
`, dir)
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w := NewWatcher(filepath.Join(t.TempDir(), "cursor"), nil)
	w.journalctl = filepath.Join(dir, "journalctl")
	return &fakeJournal{dir}, w
}

func (f *fakeJournal) start(k int, out []string, stay bool, stderr string) {
	if len(out) > 0 {
		os.WriteFile(filepath.Join(f.dir, fmt.Sprint("out", k)), []byte(strings.Join(out, "\n")+"\n"), 0o644)
	}
	if stay {
		os.WriteFile(filepath.Join(f.dir, fmt.Sprint("stay", k)), nil, 0o644)
	}
	if stderr != "" {
		os.WriteFile(filepath.Join(f.dir, fmt.Sprint("err", k)), []byte(stderr), 0o644)
	}
}

func (f *fakeJournal) args() []string {
	b, _ := os.ReadFile(filepath.Join(f.dir, "args"))
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

type run struct {
	mu          sync.Mutex
	events      []detect.Event
	errs        []error
	unavailable int
	stop        func()
	done        chan struct{}
}

func start(w *Watcher, restart time.Duration) *run {
	r := &run{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		w.Run(ctx, restart, func(error) { r.mu.Lock(); r.unavailable++; r.mu.Unlock() },
			func(err error) { r.mu.Lock(); r.errs = append(r.errs, err); r.mu.Unlock() },
			func(e detect.Event) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() })
		close(r.done)
	}()
	r.stop = func() { cancel(); <-r.done }
	return r
}

func (r *run) wait(t *testing.T, n int) []detect.Event {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		r.mu.Lock()
		got := append([]detect.Event(nil), r.events...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
	}
	t.Fatalf("want %d events, have %d (errors %v)", n, len(r.events), r.errs)
	return nil
}

func TestKnocksAreFollowedInTheJournal(t *testing.T) {
	f, w := newFakeJournal(t)
	f.start(1, []string{
		line("kernel", "[UFW BLOCK] IN=wlan0 OUT= MAC=aa SRC=203.0.113.9 DST=192.0.2.20 LEN=44 PROTO=TCP SPT=51000 DPT=22 WINDOW=1024 SYN"),
		line("kernel", "[UFW BLOCK] IN= OUT=wlan0 SRC=192.0.2.20 DST=203.0.113.9 PROTO=UDP SPT=5353 DPT=5353"), // outgoing: not a knock
		line("kernel", "usb 1-2: new device"),
		line("sshd-session", "Failed password for invalid user admin‮ from 198.51.100.7 port 40022 ssh2"),
		line("sshd", "Accepted publickey for alex from 192.0.2.5 port 5000 ssh2"),
		`{"MESSAGE":[1,2,3],"SYSLOG_IDENTIFIER":"kernel","__CURSOR":"s=abc;i=Z"}`,
	}, true, "")
	r := start(w, time.Hour)
	defer r.stop()
	ev := r.wait(t, 2)
	if ev[0].Kind != "firewall_block" || ev[0].Fields["src"] != "203.0.113.9" || ev[0].Fields["dst_port"] != "22" || ev[0].Fields["spoofable"] != "1" {
		t.Errorf("block: %+v", ev[0])
	}
	if ev[1].Kind != "login_failure" || ev[1].Fields["src"] != "198.51.100.7" || ev[1].Fields["user"] != "admin?" {
		t.Errorf("login: %+v", ev[1])
	}
	a := f.args()
	if len(a) != 1 || !strings.Contains(a[0], "--follow") || !strings.Contains(a[0], "--since=-10min") || strings.Contains(a[0], "cursor") || !strings.Contains(a[0], "_TRANSPORT=kernel") {
		t.Errorf("first start: %q", a)
	}
	// the cursor of the last entry read (the byte-array one counts too) is written shortly after, while journalctl runs on
	time.Sleep(saveAfter + 300*time.Millisecond)
	if b, _ := os.ReadFile(w.CursorPath); strings.TrimSpace(string(b)) != "s=abc;i=Z" {
		t.Errorf("cursor file: %q", b)
	}
}

// journalctl ending is not the end: it is started again after the last entry read, so nothing is read twice or skipped.
func TestAFollowerThatEndsIsStartedAgainAfterTheLastEntry(t *testing.T) {
	f, w := newFakeJournal(t)
	f.start(1, []string{line("sshd", "Invalid user bob from 198.51.100.8 port 1 ssh2"), `{"MESSAGE":"x","__CURSOR":"s=abc;i=K"}`}, false, "")
	f.start(2, []string{line("sshd", "Invalid user eve from 198.51.100.9 port 1 ssh2")}, true, "")
	r := start(w, 50*time.Millisecond)
	defer r.stop()
	ev := r.wait(t, 2)
	if ev[0].Fields["user"] != "bob" || ev[1].Fields["user"] != "eve" {
		t.Fatalf("%+v", ev)
	}
	a := f.args()
	if len(a) != 2 || !strings.Contains(a[1], "--after-cursor=s=abc;i=K") || strings.Contains(a[1], "--since") {
		t.Fatalf("second start: %q", a)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.errs) != 1 || !strings.Contains(r.errs[0].Error(), "journalctl ended") {
		t.Fatalf("the end of the first journalctl is said once: %v", r.errs)
	}
}

// A restart of heimdalld goes on from the cursor file, and an entry read just before stopping is in the file afterwards.
func TestTheCursorFileCarriesOverARestart(t *testing.T) {
	f, w := newFakeJournal(t)
	os.WriteFile(w.CursorPath, []byte("s=abc;i=5\n"), 0o600)
	f.start(1, []string{`{"MESSAGE":"x","__CURSOR":"s=abc;i=6"}`}, true, "")
	r := start(w, time.Hour)
	time.Sleep(200 * time.Millisecond)
	r.stop() // before saveAfter: the save on the way out writes it
	if a := f.args(); len(a) != 1 || !strings.Contains(a[0], "--after-cursor=s=abc;i=5") || strings.Contains(a[0], "--since") {
		t.Fatalf("start after a restart: %q", a)
	}
	if b, _ := os.ReadFile(w.CursorPath); strings.TrimSpace(string(b)) != "s=abc;i=6" {
		t.Fatalf("cursor file after stopping: %q", b)
	}
	// a cursor file someone filled with junk is not passed on
	os.WriteFile(w.CursorPath, []byte(strings.Repeat("x", 600)), 0o600)
	if c := w.cursor(); c != "" {
		t.Fatalf("junk cursor used: %q", c)
	}
}

func TestNoJournalAccessIsReportedOnce(t *testing.T) {
	f, w := newFakeJournal(t)
	f.start(1, nil, false, "No journal files were opened due to insufficient permissions.\n")
	r := start(w, 10*time.Millisecond)
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the source did not stop")
	}
	if r.unavailable != 1 || len(f.args()) != 1 {
		t.Errorf("unavailable %d times, %d starts", r.unavailable, len(f.args()))
	}
}
