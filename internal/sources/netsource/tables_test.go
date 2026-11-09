package netsource

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// tcpLine is one /proc/net/tcp row: local and remote IPv4 address and port, state, socket inode.
func tcpLine(local [4]byte, lport int, remote [4]byte, rport, state int, ino uint64) string {
	hx := func(a [4]byte) string { return fmt.Sprintf("%02X%02X%02X%02X", a[3], a[2], a[1], a[0]) }
	return fmt.Sprintf("   0: %s:%04X %s:%04X %02X 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 20 4 30 10 -1\n",
		hx(local), lport, hx(remote), rport, state, ino)
}

// Every watcher sees the same read, each keeps its own behaviour (the port check and the listener check learn on their
// first look, the connection log marks its first look as learning), and one with a longer interval skips reads.
func TestTablesShareOneReadBetweenTheWatchers(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "net"), 0o755)
	os.MkdirAll(filepath.Join(root, "4242", "fd"), 0o755)
	os.WriteFile(filepath.Join(root, "4242", "comm"), []byte("curl\n"), 0o644)
	os.Symlink("socket:[777]", filepath.Join(root, "4242", "fd", "5"))
	os.Symlink("socket:[778]", filepath.Join(root, "4242", "fd", "6"))
	any, lo, far, far2 := [4]byte{0, 0, 0, 0}, [4]byte{127, 0, 0, 1}, [4]byte{5, 0, 0, 10}, [4]byte{5, 0, 0, 11}
	write := func(lines ...string) {
		os.WriteFile(filepath.Join(root, "net/tcp"), []byte(tcpHeader+strings.Join(lines, "")), 0o644)
	}
	write(tcpLine(any, 8080, any, 0, tcpListen, 1), tcpLine(lo, 40000, far, 443, tcpEstablished, 777))

	tb := &Tables{paths: []string{filepath.Join(root, "net/tcp"), filepath.Join(root, "net/tcp6")}}
	tb.Ports(newPortWatcherWithPaths([]int{8080}, nil), 15*time.Second, nil, nil)
	tb.Connections(newConnWatcher(root, filepath.Join(t.TempDir(), "conn.json"), ""), 10*time.Second, nil, nil)
	lw := NewListenWatcher()
	lw.procRoot = root
	tb.Listeners(lw, 30*time.Second)
	if tb.tick() != 10*time.Second {
		t.Fatalf("tick %s", tb.tick())
	}
	var got []detect.Event
	emit := func(e detect.Event) { got = append(got, e) }
	start := time.Now()
	kinds := func() string {
		var k []string
		for _, e := range got {
			k = append(k, e.Kind+":"+e.Fields["learning"]+e.Fields["port"])
		}
		got = nil
		return strings.Join(k, " ")
	}

	tb.step(start, 10*time.Second, true, emit)
	if k := kinds(); k != "new_connection:1" { // the bind on 8080 and the listener were there before: learned
		t.Fatalf("first read: %s", k)
	}
	// 10 s on: a second connection and a new listener; the port check (15 s, due within half a tick) and the connection
	// log look, the listener check (30 s) does not yet
	write(tcpLine(any, 8080, any, 0, tcpListen, 1), tcpLine(any, 9090, any, 0, tcpListen, 2),
		tcpLine(lo, 40000, far, 443, tcpEstablished, 777), tcpLine(lo, 40001, far2, 443, tcpEstablished, 778))
	tb.step(start.Add(10*time.Second), 10*time.Second, false, emit)
	if k := kinds(); k != "new_connection:" {
		t.Fatalf("second read: %s", k)
	}
	tb.step(start.Add(20*time.Second), 10*time.Second, false, emit)
	tb.step(start.Add(30*time.Second), 10*time.Second, false, emit)
	if k := kinds(); k != "new_listener:9090" {
		t.Fatalf("third and fourth read: %s", k)
	}
	// a peer on a watched port is reported by the port check
	write(tcpLine(any, 8080, any, 0, tcpListen, 1), tcpLine(far, 8080, far2, 5000, tcpEstablished, 9))
	tb.step(start.Add(40*time.Second), 10*time.Second, false, emit)
	if k := kinds(); k != "non_loopback_peer: new_connection:" { // an established connection off the machine is in the connection log too
		t.Fatalf("fifth read: %s", k)
	}
}

func TestTablesWithoutProcTellEachWatcherOnceAndStop(t *testing.T) {
	dir := t.TempDir()
	tb := &Tables{paths: []string{filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")}}
	var told []string
	tb.Ports(newPortWatcherWithPaths([]int{8080}, nil), time.Second, func(error) { told = append(told, "ports") }, nil)
	tb.Connections(newConnWatcher(dir, "", ""), time.Second, func(error) { told = append(told, "conn") }, nil)
	done := make(chan struct{})
	go func() { tb.Run(context.Background(), func(detect.Event) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	if strings.Join(told, ",") != "ports,conn" {
		t.Fatalf("told %v", told)
	}
}

// fakeProcTree writes a /proc with the given processes (pid -> name) and established connections (socket inode -> holder
// and remote address), replacing whatever was there.
type fakeConn struct {
	pid    int
	remote [4]byte
	port   int
}

func writeProcTree(t *testing.T, root string, procs map[int]string, conns map[uint64]fakeConn) {
	t.Helper()
	ents, _ := os.ReadDir(root)
	for _, e := range ents {
		os.RemoveAll(filepath.Join(root, e.Name()))
	}
	os.MkdirAll(filepath.Join(root, "net"), 0o755)
	var lines []string
	inos := make([]uint64, 0, len(conns))
	for ino := range conns {
		inos = append(inos, ino)
	}
	sort.Slice(inos, func(i, j int) bool { return inos[i] < inos[j] })
	fd := map[int]int{}
	for pid, comm := range procs {
		os.MkdirAll(filepath.Join(root, fmt.Sprint(pid), "fd"), 0o755)
		os.WriteFile(filepath.Join(root, fmt.Sprint(pid), "comm"), []byte(comm+"\n"), 0o644)
		for k := 0; k < 3; k++ { // a process has other files open too
			os.Symlink(fmt.Sprintf("/dev/pts/%d", k), filepath.Join(root, fmt.Sprint(pid), "fd", fmt.Sprint(k)))
		}
		fd[pid] = 3
	}
	for _, ino := range inos {
		c := conns[ino]
		lines = append(lines, tcpLine([4]byte{192, 0, 2, 20}, 30000+int(ino%30000), c.remote, c.port, tcpEstablished, ino))
		if _, ok := procs[c.pid]; ok {
			os.Symlink(fmt.Sprintf("socket:[%d]", ino), filepath.Join(root, fmt.Sprint(c.pid), "fd", fmt.Sprint(fd[c.pid])))
			fd[c.pid]++
		}
	}
	os.WriteFile(filepath.Join(root, "net/tcp"), []byte(tcpHeader+strings.Join(lines, "")), 0o644)
}

// The owner cache must not change what is reported: connections open and close, processes come and go, and the
// connection log with the cache reports exactly what one walking /proc on every look does, while reading far fewer
// processes' files.
func TestConnOwnerCacheReportsWhatAFullWalkReports(t *testing.T) {
	rng := rand.New(rand.NewSource(1109))
	root := t.TempDir()
	procs := map[int]string{}
	conns := map[uint64]fakeConn{}
	names := []string{"vivaldi-bin", "steam", "discord", "curl", "ollama", "sarina", "python3", "git"}
	nextPid, nextIno := 100, uint64(1000)
	for i := 0; i < 40; i++ {
		procs[nextPid] = names[rng.Intn(len(names))]
		nextPid++
	}
	cached := newConnWatcher(root, filepath.Join(t.TempDir(), "a.json"), "")
	walked := newConnWatcher(root, filepath.Join(t.TempDir(), "b.json"), "")
	pids := func() []int {
		var p []int
		for pid := range procs {
			p = append(p, pid)
		}
		sort.Ints(p)
		return p
	}
	total := 0
	for step := 0; step < 300; step++ {
		for k := rng.Intn(4); k > 0; k-- { // new connections, mostly from the processes that already have some
			p := pids()
			pid := p[rng.Intn(len(p))]
			for ino, c := range conns {
				if rng.Intn(2) == 0 {
					pid = c.pid
					_ = ino
					break
				}
			}
			conns[nextIno] = fakeConn{pid, [4]byte{203, 0, byte(rng.Intn(4)), byte(rng.Intn(250))}, []int{443, 80, 27015}[rng.Intn(3)]}
			nextIno++
		}
		for ino := range conns {
			if rng.Intn(6) == 0 {
				delete(conns, ino)
			}
		}
		if rng.Intn(10) == 0 { // a process ends (its connections with it), another starts
			p := pids()
			gone := p[rng.Intn(len(p))]
			delete(procs, gone)
			for ino, c := range conns {
				if c.pid == gone {
					delete(conns, ino)
				}
			}
			procs[nextPid] = names[rng.Intn(len(names))]
			nextPid++
		}
		if rng.Intn(15) == 0 { // a socket whose holder Heimdall cannot see
			conns[nextIno] = fakeConn{99999, [4]byte{198, 51, 100, byte(rng.Intn(5))}, 443}
			nextIno++
		}
		writeProcTree(t, root, procs, conns)
		a, errA := cached.Poll()
		walked.owned = nil // walk /proc on every look, as before the cache
		b, errB := walked.Poll()
		if !errors.Is(errA, errB) || !reflect.DeepEqual(strip(a), strip(b)) {
			t.Fatalf("step %d: cached %v %v\nwalked %v %v", step, strip(a), errA, strip(b), errB)
		}
		total += len(a)
	}
	if total < 300 {
		t.Fatalf("only %d events: the churn did not exercise much", total)
	}
	t.Logf("%d events; processes whose files were read: %d with the cache, %d walking every time", total, cached.scanned, walked.scanned)
}

func strip(events []detect.Event) []string {
	var out []string
	for _, e := range events {
		out = append(out, fmt.Sprintf("%s %s %v", e.Kind, e.Text, e.Fields))
	}
	return out
}

// A connection whose owner is known is not looked for again, a new one is looked for first in the processes that already
// hold connections, and a closed one is forgotten.
func TestConnOwnersAreLookedForOnce(t *testing.T) {
	root := t.TempDir()
	procs := map[int]string{100: "steam", 200: "vivaldi-bin", 300: "bash", 400: "git"}
	conns := map[uint64]fakeConn{1: {200, [4]byte{203, 0, 113, 1}, 443}}
	writeProcTree(t, root, procs, conns)
	w := newConnWatcher(root, filepath.Join(t.TempDir(), "s.json"), "")
	if ev, _ := w.Poll(); len(ev) != 1 || ev[0].Fields["process"] != "vivaldi-bin" {
		t.Fatalf("%v", strip(ev))
	}
	before := w.scanned
	w.Poll()
	if w.scanned != before {
		t.Fatalf("an unchanged connection made a walk: %d processes read", w.scanned-before)
	}
	conns[2] = fakeConn{200, [4]byte{203, 0, 113, 2}, 443}
	writeProcTree(t, root, procs, conns)
	if ev, _ := w.Poll(); len(ev) != 1 || ev[0].Fields["process"] != "vivaldi-bin" || w.scanned != before+1 {
		t.Fatalf("new connection of a known process: %v, %d processes read", strip(ev), w.scanned-before)
	}
	delete(conns, 1)
	delete(conns, 2)
	writeProcTree(t, root, procs, conns)
	w.Poll()
	if len(w.owned) != 0 {
		t.Fatalf("closed connections kept: %v", w.owned)
	}
}
