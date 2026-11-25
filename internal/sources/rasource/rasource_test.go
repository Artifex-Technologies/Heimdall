package rasource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
)

func TestPackageNames(t *testing.T) {
	for in, want := range map[string]string{"tailscale-1.104.2-1": "tailscale", "zerotier-one-1.14.2-2": "zerotier-one", "x": "", "ALPM_DB_VERSION": ""} {
		if got := PackageName(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func touch(t *testing.T, p string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, nil, 0o644)
}

func TestInstalledToolsAndNewTunnelsAreReported(t *testing.T) {
	d := t.TempDir()
	w := New(remoteaccess.Builtin())
	w.PacmanDir, w.NetDir = filepath.Join(d, "local"), filepath.Join(d, "net")
	w.ProcDir, w.Footholds.Root = filepath.Join(d, "proc"), filepath.Join(d, "root") // never this computer's
	os.MkdirAll(filepath.Join(w.PacmanDir, "bash-5.2-1"), 0o755)
	os.MkdirAll(filepath.Join(w.PacmanDir, "tailscale-1.104.2-1"), 0o755)
	touch(t, filepath.Join(w.NetDir, "lo", "uevent"))
	touch(t, filepath.Join(w.NetDir, "wg-home", "tun_flags")) // a tunnel already there at start: the computer's own
	ev := w.Poll()
	if len(ev) != 1 || ev[0].Fields["provider"] != "tailscale" || ev[0].Fields["signal"] != "package" {
		t.Fatalf("first poll: %+v", ev)
	}
	if len(w.Poll()) != 0 {
		t.Fatal("nothing changed: nothing to report")
	}
	os.MkdirAll(filepath.Join(w.PacmanDir, "ngrok-3.19-1"), 0o755)
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(w.PacmanDir, later, later)
	touch(t, filepath.Join(w.NetDir, "zt5u4nvqrn", "uevent"))
	os.MkdirAll(filepath.Join(w.NetDir, "wg0"), 0o755)
	os.WriteFile(filepath.Join(w.NetDir, "wg0", "uevent"), []byte("DEVTYPE=wireguard\nINTERFACE=wg0\n"), 0o644)
	got := map[string]string{}
	for _, e := range w.Poll() {
		got[e.Fields["signal"]+":"+e.Fields["package"]+e.Fields["iface"]] = e.Fields["provider"]
	}
	if got["package:ngrok"] != "ngrok" || got["iface:zt5u4nvqrn"] != "zerotier" || len(got) != 3 {
		t.Fatalf("second poll: %v", got)
	}
	if _, ok := got["tunnel:wg0"]; !ok {
		t.Fatalf("a new WireGuard interface: %v", got)
	}
}

func TestALimboSandboxCableIsNotATunnel(t *testing.T) {
	d := t.TempDir()
	w := New(remoteaccess.Builtin())
	w.PacmanDir, w.NetDir = filepath.Join(d, "local"), filepath.Join(d, "net")
	w.ProcDir, w.Footholds.Root = filepath.Join(d, "proc"), filepath.Join(d, "root") // never this computer's
	os.MkdirAll(w.PacmanDir, 0o755)
	touch(t, filepath.Join(w.NetDir, "lo", "uevent"))
	w.Poll()
	// the tap appears before Limbo plugs it into its bridge: not reported yet, looked at again
	touch(t, filepath.Join(w.NetDir, "vl-test", "tun_flags"))
	os.MkdirAll(filepath.Join(w.NetDir, "lb-test"), 0o755)
	if ev := w.Poll(); len(ev) != 0 {
		t.Fatalf("unplugged tap: %+v", ev)
	}
	os.Symlink("../lb-test", filepath.Join(w.NetDir, "vl-test", "master"))
	if ev := w.Poll(); len(ev) != 0 {
		t.Fatalf("Limbo's own tap: %+v", ev)
	}
	// a tap that only borrows the name (on another bridge) is still reported
	touch(t, filepath.Join(w.NetDir, "vl-other", "tun_flags"))
	os.Symlink("../br0", filepath.Join(w.NetDir, "vl-other", "master"))
	touch(t, filepath.Join(w.NetDir, "tun9", "tun_flags"))
	got := map[string]bool{}
	for _, e := range w.Poll() {
		got[e.Fields["iface"]] = true
	}
	if !got["vl-other"] || !got["tun9"] {
		t.Fatalf("a tap on another bridge and an ordinary new tunnel are reported: %v", got)
	}
	// a tap that never gets plugged in is reported after three looks
	touch(t, filepath.Join(w.NetDir, "vl-ghost", "tun_flags"))
	n := 0
	for i := 0; i < 5; i++ {
		for _, e := range w.Poll() {
			if e.Fields["iface"] == "vl-ghost" {
				n++
			}
		}
	}
	if n != 1 {
		t.Fatalf("vl-ghost reported %d times", n)
	}
}

// fakeProc writes a /proc for TestTheKernelsSide: two catalog modules and an ordinary one; raw packet sockets held by
// NetworkManager (usual), by a program calling itself kworkerd (not), and by no process Heimdall can see; three shells,
// one reading a TCP connection, one a Unix socket (not in the TCP and UDP tables), one a terminal no one here holds; and
// (HEI-79) four shells on terminals whose master is held by python3 with a connection to another computer (a reverse
// shell), by sshd-session with one (a login), by a program whose connection stays on this computer, and by one that only
// listens. The Rust port reads the same tree (rust/heimdall/src/sources/files.rs, the_kernels_side).
func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, text string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(rel, target string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	write("modules", "ksmbd 344064 0 - Live 0x0000000000000000\next4 1101824 2 - Live 0x0000000000000000\nnvmet_tcp 45056 0 - Live 0x0000000000000000\n")
	write("net/packet", "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n"+
		"0000000000000000 3      3    0003   2     1 0      0      100\n"+
		"0000000000000000 3      3    0800   0     1 0      0      200\n"+
		"0000000000000000 3      2    0003   3     1 0      0      300\n"+
		"0000000000000000 3      3    0003   0     1 0      0      0\n")
	write("net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0A00000A:9C40 0500000A:115C 01 00000000:00000000 00:00000000 00000000  1000        0 500 1\n"+
		"   1: 0A00000A:9C41 0600000A:115D 01 00000000:00000000 00:00000000 00000000  1000        0 700 1\n"+
		"   2: 0A00000A:0016 0700000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 800 1\n"+
		"   3: 0100007F:1388 0100007F:A028 01 00000000:00000000 00:00000000 00000000  1000        0 900 1\n"+
		"   4: 00000000:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1000 1\n")
	write("10/comm", "NetworkManager\n")
	link("10/fd/5", "socket:[100]")
	write("20/comm", "kworkerd\n")
	link("20/fd/0", "/dev/null")
	link("20/fd/3", "socket:[200]")
	write("30/comm", "bash\n")
	link("30/fd/0", "socket:[500]")
	write("31/comm", "bash\n")
	link("31/fd/0", "socket:[600]")
	write("32/comm", "bash\n")
	link("32/fd/0", "/dev/pts/1")
	pty := func(holder, name, n, sock, shell string) {
		write(holder+"/comm", name+"\n")
		link(holder+"/fd/3", "/dev/ptmx")
		write(holder+"/fdinfo/3", "pos:\t0\nflags:\t02100002\nmnt_id:\t40\nino:\t125\ntty-index:\t"+n+"\n")
		link(holder+"/fd/4", "socket:["+sock+"]")
		write(shell+"/comm", "bash\n")
		link(shell+"/fd/0", "/dev/pts/"+n)
	}
	pty("40", "python3", "2", "700", "41")
	pty("50", "sshd-session", "3", "800", "51")
	pty("60", "node", "4", "900", "61")
	pty("70", "ttyd", "5", "1000", "71")
	return root
}

// TestTheKernelsSide (HEI-12, HEI-79): the catalog's kernel modules, a raw packet listener outside the usual programs, a
// shell reading a TCP connection and one whose terminal python3 feeds from one are each one remote_access event, once; the
// usual raw listener, one whose owner cannot be seen, the ordinary module, the shells on a Unix socket or an unheld
// terminal, a login's terminal and terminals held by programs talking only to this computer or only listening are none.
func TestTheKernelsSide(t *testing.T) {
	w := New(remoteaccess.Builtin())
	w.PacmanDir, w.NetDir, w.ProcDir = filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "none"), fakeProc(t)
	w.Footholds.Root = filepath.Join(t.TempDir(), "none")
	var got []string
	for _, e := range w.Poll() {
		got = append(got, e.Fields["signal"]+" "+e.Fields["provider"]+" "+e.Fields["pid"]+" "+e.Fields["module"]+e.Fields["connection"]+" | "+e.Text)
	}
	want := []string{
		"module ksmbd  ksmbd | the kernel module ksmbd (ksmbd, the kernel's SMB file server) was loaded",
		"module nvmet  nvmet_tcp | the kernel module nvmet_tcp (the kernel's NVMe over Fabrics target) was loaded",
		"raw-listener kworkerd 20  | kworkerd (pid 20) reads raw network packets",
		"socket-shell bash 30 tcp 10.0.0.10:40000 -> 10.0.0.5:4444 | the shell bash (pid 30) takes its input from a network connection (tcp 10.0.0.10:40000 -> 10.0.0.5:4444)",
		"socket-shell bash 41 tcp 10.0.0.10:40001 -> 10.0.0.6:4445 | the shell bash (pid 41) takes its input from a network connection through the terminal /dev/pts/2, held by python3 (pid 40) (tcp 10.0.0.10:40001 -> 10.0.0.6:4445)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if again := w.Poll(); len(again) != 0 {
		t.Errorf("each once: %+v", again)
	}
}
