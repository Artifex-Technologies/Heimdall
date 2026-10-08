package netsource

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real /proc/net/tcp fixture lines, hand-verified against the kernel's
// encoding (address bytes reversed per 4-byte group, port big-endian,
// state as a raw hex byte):
//   - line 0: 127.0.0.1:8765 LISTEN                          (loopback bind -- ignored)
//   - line 1: 127.0.0.1:8765 <- 127.0.0.1:51242 ESTABLISHED   (loopback peer -- ignored)
//   - line 2: 0.0.0.0:8080 LISTEN                             (non-loopback bind -- violation)
//   - line 3: 127.0.0.1:8080 <- 5.0.0.10:51242 ESTABLISHED    (non-loopback peer -- violation)
const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:223D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:223D 0100007F:C82A 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0
   3: 0100007F:1F90 0A000005:C82A 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 20 4 30 10 -1
`

func TestParseProcNetTCP(t *testing.T) {
	entries, err := ParseProcNetTCP(strings.NewReader(procNetTCPFixture))
	if err != nil {
		t.Fatalf("ParseProcNetTCP: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d: %+v", len(entries), entries)
	}

	listen := entries[0]
	if listen.LocalIP.String() != "127.0.0.1" || listen.LocalPort != 8765 || listen.State != tcpListen {
		t.Fatalf("entry 0: expected 127.0.0.1:8765 LISTEN, got %+v", listen)
	}

	established := entries[1]
	if established.RemoteIP.String() != "127.0.0.1" || established.RemotePort != 51242 || established.State != tcpEstablished {
		t.Fatalf("entry 1: expected remote 127.0.0.1:51242 ESTABLISHED, got %+v", established)
	}

	unspecified := entries[2]
	if !unspecified.LocalIP.IsUnspecified() || unspecified.LocalPort != 8080 {
		t.Fatalf("entry 2: expected 0.0.0.0:8080, got %+v", unspecified)
	}

	external := entries[3]
	if external.RemoteIP.String() != "5.0.0.10" || external.RemotePort != 51242 {
		t.Fatalf("entry 3: expected remote 5.0.0.10:51242, got %+v", external)
	}
}

func TestParseHexIPv6Loopback(t *testing.T) {
	// ::1 in network order is 15 zero bytes then 0x01, split into 4
	// groups of 4 bytes each stored little-endian on disk -- only the
	// last group is non-zero, reversed from 00 00 00 01 to 01 00 00 00.
	hexStr := "00000000" + "00000000" + "00000000" + "01000000"
	got, err := parseHexIP(hexStr)
	if err != nil {
		t.Fatalf("parseHexIP: %v", err)
	}
	if !got.Equal(net.ParseIP("::1")) {
		t.Fatalf("expected ::1, got %s", got)
	}
	if !got.IsLoopback() {
		t.Fatalf("expected %s to report IsLoopback() true", got)
	}
}

func TestPortWatcherPollDetectsNewViolationsOnce(t *testing.T) {
	dir := t.TempDir()
	tcpPath := filepath.Join(dir, "tcp")
	tcp6Path := filepath.Join(dir, "tcp6") // deliberately absent -- must not error the poll

	writeFixture(t, tcpPath, procNetTCPFixture)

	w := newPortWatcherWithPaths([]int{8765, 8080}, []string{tcpPath, tcp6Path})
	events, err := w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// port 8765: LISTEN on loopback + ESTABLISHED from loopback -> no violation.
	// port 8080: LISTEN on 0.0.0.0 + ESTABLISHED from 5.0.0.10 -> two events.
	if len(events) != 2 {
		t.Fatalf("expected 2 violation events, got %d: %+v", len(events), events)
	}

	kinds := map[string]bool{}
	for _, e := range events {
		kinds[e.Kind] = true
	}
	if !kinds["non_loopback_bind"] || !kinds["non_loopback_peer"] {
		t.Fatalf("expected both a bind and a peer violation, got %+v", events)
	}

	// A second poll of the same unchanged state must not re-alert.
	events, err = w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no repeat events for an unchanged violation, got %+v", events)
	}
}

func TestPortWatcherIgnoresUnwatchedPorts(t *testing.T) {
	dir := t.TempDir()
	tcpPath := filepath.Join(dir, "tcp")
	writeFixture(t, tcpPath, procNetTCPFixture)

	w := newPortWatcherWithPaths([]int{9999}, []string{tcpPath})
	events, err := w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events for a port not being watched, got %+v", events)
	}
}

func TestPortWatcherPollMissingProc(t *testing.T) {
	dir := t.TempDir()
	w := newPortWatcherWithPaths([]int{8765}, []string{filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")})
	if _, err := w.Poll(); err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected an os.IsNotExist error when every path is missing, got %v", err)
	}
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}
