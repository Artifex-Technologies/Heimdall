package fwsource

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

var n int

func line(ident, msg string) string {
	n++
	b, _ := json.Marshal(map[string]string{"MESSAGE": msg, "SYSLOG_IDENTIFIER": ident, "__REALTIME_TIMESTAMP": "1761170000000000", "__CURSOR": "s=abc;i=" + string(rune('0'+n))})
	return string(b)
}

func TestKnocksAreReadFromTheJournal(t *testing.T) {
	w := NewWatcher(filepath.Join(t.TempDir(), "cursor"), nil)
	var gotArgs []string
	w.run = func(_ context.Context, args ...string) ([]byte, error) {
		gotArgs = args
		return []byte(strings.Join([]string{
			line("kernel", "[UFW BLOCK] IN=wlan0 OUT= MAC=aa SRC=203.0.113.9 DST=192.168.1.20 LEN=44 PROTO=TCP SPT=51000 DPT=22 WINDOW=1024 SYN"),
			line("kernel", "[UFW BLOCK] IN= OUT=wlan0 SRC=192.168.1.20 DST=203.0.113.9 PROTO=UDP SPT=5353 DPT=5353"), // outgoing: not a knock
			line("kernel", "usb 1-2: new device"),
			line("sshd-session", "Failed password for invalid user admin‮ from 198.51.100.7 port 40022 ssh2"),
			line("sshd", "Accepted publickey for zlothra from 192.168.1.5 port 5000 ssh2"),
			`{"MESSAGE":[1,2,3],"SYSLOG_IDENTIFIER":"kernel","__CURSOR":"s=abc;i=Z"}`,
		}, "\n")), nil
	}
	ev, err := w.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 2 {
		t.Fatalf("got %d events: %+v", len(ev), ev)
	}
	if ev[0].Kind != "firewall_block" || ev[0].Fields["src"] != "203.0.113.9" || ev[0].Fields["dst_port"] != "22" || ev[0].Fields["spoofable"] != "1" {
		t.Errorf("block: %+v", ev[0])
	}
	if ev[1].Kind != "login_failure" || ev[1].Fields["src"] != "198.51.100.7" || ev[1].Fields["user"] != "admin?" {
		t.Errorf("login: %+v", ev[1])
	}
	a := strings.Join(gotArgs, " ")
	if !strings.Contains(a, "--since=-10min") || strings.Contains(a, "cursor") || !strings.Contains(a, "_TRANSPORT=kernel") {
		t.Errorf("first run args: %s", a)
	}
	// the next poll continues after the last entry read (the byte-array one counts too)
	w.Poll(context.Background())
	a = strings.Join(gotArgs, " ")
	if !strings.Contains(a, "--after-cursor=s=abc;i=Z") || strings.Contains(a, "--since") {
		t.Errorf("second run args: %s", a)
	}
}

func TestNoJournalAccessIsReportedOnce(t *testing.T) {
	w := NewWatcher(filepath.Join(t.TempDir(), "cursor"), nil)
	w.run = func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("exit status 1: No journal files were opened due to insufficient permissions.")
	}
	if _, err := w.Poll(context.Background()); !errors.Is(err, ErrNoAccess) {
		t.Errorf("got %v", err)
	}
}
