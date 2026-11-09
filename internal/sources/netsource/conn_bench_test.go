package netsource

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// oldOwners is the owner lookup before the cache (2026-11-09): readlink of every open file of every process, every look.
func oldOwners(procRoot string, want map[uint64]bool) map[uint64]int {
	out := map[uint64]int{}
	dirs, _ := os.ReadDir(procRoot)
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err == nil && want[ino] {
				out[ino] = pid
			}
		}
	}
	return out
}

// go test -run NONE -bench ConnOwners ./internal/sources/netsource: finding the owners of 80 connections among 300 processes
// with 20 open files each. old: the walk every look. steady: nothing new. new-connection: one new connection (of a process
// that has some already) per look. unknown-owner: one new socket no visible process holds, the worst case (a full walk).
func BenchmarkConnOwners(b *testing.B) {
	root := b.TempDir()
	rng := rand.New(rand.NewSource(1))
	procs := map[int]string{}
	for pid := 100; pid < 400; pid++ {
		procs[pid] = "proc"
	}
	conns := map[uint64]fakeConn{} // as on a desktop: half of them a browser's, a quarter a game launcher's, the rest anyone's
	for ino := uint64(1); ino <= 80; ino++ {
		pid := 100 + rng.Intn(300)
		switch {
		case ino <= 40:
			pid = 250
		case ino <= 60:
			pid = 333
		}
		conns[ino] = fakeConn{pid, [4]byte{203, 0, 113, byte(ino)}, 443}
	}
	writeProcTree(&testing.T{}, root, procs, conns)
	for pid := 100; pid < 400; pid++ {
		for k := 3; k < 20; k++ {
			os.Symlink("/dev/null", filepath.Join(root, fmt.Sprint(pid), "fd", fmt.Sprintf("x%d", k)))
		}
	}
	want := map[uint64]bool{}
	for ino := range conns {
		want[ino] = true
	}
	b.Run("old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			oldOwners(root, want)
		}
	})
	b.Run("steady", func(b *testing.B) {
		w := newConnWatcher(root, "", "")
		w.resolve(want)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w.resolve(want)
		}
	})
	b.Run("new-connection", func(b *testing.B) {
		w := newConnWatcher(root, "", "")
		w.resolve(want)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			delete(w.owned, uint64(1+i%80)) // as if this connection had just appeared
			w.resolve(want)
		}
	})
	b.Run("unknown-owner", func(b *testing.B) {
		w := newConnWatcher(root, "", "")
		w.resolve(want)
		with := map[uint64]bool{999999: true}
		for ino := range want {
			with[ino] = true
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			delete(w.owned, 999999)
			w.resolve(with)
		}
	})
}

// The same on this computer's real /proc (as the user running the test: only that user's processes are visible).
func BenchmarkConnOwnersRealProc(b *testing.B) {
	entries, err := readTables([]string{"/proc/net/tcp", "/proc/net/tcp6"})
	if err != nil {
		b.Skip(err)
	}
	want := map[uint64]bool{}
	for _, e := range entries {
		if e.State == tcpEstablished && !e.RemoteIP.IsLoopback() && !e.RemoteIP.IsUnspecified() {
			want[e.Inode] = true
		}
	}
	b.Run("old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			oldOwners("/proc", want)
		}
	})
	b.Run("steady", func(b *testing.B) {
		w := NewConnWatcher("", "")
		w.resolve(want)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w.resolve(want)
		}
	})
}
