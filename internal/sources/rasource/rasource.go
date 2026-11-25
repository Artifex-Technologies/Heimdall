// Package rasource reports remote-access tools by what is on the computer rather than what it does: a package from the
// remote-access catalog being installed (read again only when pacman's database folder changes), and a tunnel interface
// appearing (a catalog interface such as tailscale0 or zt*, or any new WireGuard, TUN or TAP device). Programs holding
// connections are matched by the connection watcher (netsource) with the same catalog. Two directory listings per poll; no
// packet is read.
//
// The kernel's side (HEI-12): a catalog kernel module that makes the kernel itself serve the network (ksmbd, nfsd, an NVMe
// or iSCSI target, USB/IP, RDS) being loaded (/proc/modules); a program outside the usual ones holding a raw packet socket
// (/proc/net/packet: how a backdoor such as BPFDoor waits for a secret packet with no open port); and a shell whose input
// is a TCP or UDP socket (a reverse shell). Reading other users' processes needs the connection watcher's rights
// (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH); without them only Heimdall's own are seen.
package rasource

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
	"github.com/Artifex-Technologies/Heimdall/internal/sources/netsource"
)

type Watcher struct {
	Catalog   remoteaccess.Catalog
	PacmanDir string // /var/lib/pacman/local
	NetDir    string // /sys/class/net
	ProcDir   string // /proc

	pkgSeen   map[string]bool
	pkgMtime  int64
	ifaceSeen map[string]bool
	waited    map[string]int // "vl-" taps not yet on a bridge: how many looks they have had
	started   bool
	modSeen   map[string]bool // modules loaded at the last look
	rawSeen   map[string]bool // packet sockets (inodes) looked at
	shellSeen map[string]bool // "pid|inode" of shells reading a socket
}

func New(c remoteaccess.Catalog) *Watcher {
	return &Watcher{Catalog: c, PacmanDir: "/var/lib/pacman/local", NetDir: "/sys/class/net", ProcDir: "/proc", waited: map[string]int{}}
}

// rawAllowed are the programs that hold raw packet sockets for their work: DHCP clients and servers, Wi-Fi supplicants,
// packet capture (by process name, /proc/PID/comm, at most 15 characters).
var rawAllowed = map[string]bool{
	"NetworkManager": true, "dhcpcd": true, "dhclient": true, "udhcpc": true, "systemd-network": true, "connmand": true,
	"wpa_supplicant": true, "iwd": true, "hostapd": true, "dnsmasq": true, "dhcpd": true, "kea-dhcp4": true, "pppd": true,
	"tcpdump": true, "dumpcap": true, "tshark": true, "wireshark": true, "arp-scan": true, "nmap": true, "lldpd": true,
	"avahi-autoipd": true,
}

// shells are the command interpreters a reverse shell runs (by process name).
var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true, "fish": true, "tcsh": true,
	"csh": true, "busybox": true, "pwsh": true,
}

// PackageName is the name in a pacman database entry ("tailscale-1.104.2-1" -> "tailscale").
func PackageName(entry string) string {
	parts := strings.Split(entry, "-")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

func event(text string, f map[string]string) detect.Event {
	return detect.Event{Source: "remote-access", Time: time.Now(), Kind: "remote_access", Text: text, Fields: f}
}

func (w *Watcher) packages() []detect.Event {
	fi, err := os.Stat(w.PacmanDir)
	if err != nil || fi.ModTime().UnixNano() == w.pkgMtime {
		return nil
	}
	w.pkgMtime = fi.ModTime().UnixNano()
	entries, err := os.ReadDir(w.PacmanDir)
	if err != nil {
		return nil
	}
	now := map[string]bool{}
	var out []detect.Event
	for _, e := range entries {
		name := PackageName(e.Name())
		if name == "" {
			continue
		}
		now[name] = true
		if w.pkgSeen[name] {
			continue
		}
		if p := w.Catalog.MatchPackage(name); p != nil {
			// reported on the first poll too: a remote-access tool already installed matters as much as a new one
			out = append(out, event("the package "+name+" ("+p.Name+") is installed",
				map[string]string{"provider": p.ID, "provider_name": p.Name, "ra_kind": p.Kind, "signal": "package", "package": name}))
		}
	}
	w.pkgSeen = now
	return out
}

// tunnelKind says what kind of tunnel an interface is ("wireguard", "tun"), or "" for an ordinary one.
func tunnelKind(dir string) string {
	if b, err := os.ReadFile(filepath.Join(dir, "uevent")); err == nil && strings.Contains(string(b), "DEVTYPE=wireguard") {
		return "wireguard"
	}
	if _, err := os.Stat(filepath.Join(dir, "tun_flags")); err == nil {
		return "tun"
	}
	return ""
}

// unplugged: a "vl-" tap on no bridge yet.
func unplugged(netDir, name string) bool {
	_, err := os.Lstat(filepath.Join(netDir, name, "master"))
	return strings.HasPrefix(name, "vl-") && err != nil
}

// limboGuest reports a Limbo sandbox's tap: named "vl-<guest>" and plugged into the bridge "lb-<guest>" (Limbo's
// internal/virt/names.go). Making either takes root, which could do far worse than imitate a sandbox.
func limboGuest(netDir, name string) bool {
	guest, ok := strings.CutPrefix(name, "vl-")
	if !ok || guest == "" {
		return false
	}
	master, err := os.Readlink(filepath.Join(netDir, name, "master"))
	return err == nil && filepath.Base(master) == "lb-"+guest
}

func (w *Watcher) interfaces() []detect.Event {
	entries, err := os.ReadDir(w.NetDir)
	if err != nil {
		return nil
	}
	now := map[string]bool{}
	var out []detect.Event
	for _, e := range entries {
		name := e.Name()
		now[name] = true
		if w.ifaceSeen[name] {
			continue
		}
		if p := w.Catalog.MatchIface(name); p != nil {
			out = append(out, event("the network interface "+name+" ("+p.Name+") appeared",
				map[string]string{"provider": p.ID, "provider_name": p.Name, "ra_kind": p.Kind, "signal": "iface", "iface": name}))
		} else if k := tunnelKind(filepath.Join(w.NetDir, name)); k != "" && w.started && limboGuest(w.NetDir, name) {
			// a Limbo sandbox's network cable (its tap "vl-<guest>" on its bridge "lb-<guest>"): Limbo's own, not a tunnel out
		} else if k != "" && w.started && unplugged(w.NetDir, name) && w.waited[name] < 3 {
			// Limbo makes the tap first and plugs it into its bridge a moment later: look again (three times at most)
			w.waited[name]++
			delete(now, name)
		} else if k != "" && w.started {
			// a tunnel that was already there when Heimdall started is the computer's own; a new one is worth knowing about
			out = append(out, event("a new "+k+" tunnel interface "+name+" appeared",
				map[string]string{"signal": "tunnel", "iface": name, "tunnel": k}))
		}
	}
	w.ifaceSeen = now
	return out
}

// modules reports a catalog kernel module being loaded (one read of /proc/modules); one loaded before Heimdall started is
// reported at the first look too: a server in the kernel is worth knowing about whenever it came.
func (w *Watcher) modules() []detect.Event {
	b, err := os.ReadFile(filepath.Join(w.ProcDir, "modules"))
	if err != nil {
		return nil
	}
	now := map[string]bool{}
	var out []detect.Event
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		name := f[0]
		now[name] = true
		if w.modSeen[name] {
			continue
		}
		if p := w.Catalog.MatchModule(name); p != nil {
			out = append(out, event("the kernel module "+name+" ("+p.Name+") was loaded",
				map[string]string{"provider": p.ID, "provider_name": p.Name, "ra_kind": p.Kind, "signal": "module", "module": name}))
		}
	}
	w.modSeen = now
	return out
}

// procName is a process's name (/proc/PID/comm), "" when it cannot be read.
func (w *Watcher) procName(pid string) string {
	b, err := os.ReadFile(filepath.Join(w.ProcDir, pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// socketOwners finds the process holding each socket inode in want (a walk of /proc/*/fd, stopping once all are found).
func (w *Watcher) socketOwners(want map[string]bool) map[string][2]string {
	out := map[string][2]string{}
	dirs, err := os.ReadDir(w.ProcDir)
	if err != nil {
		return out
	}
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(w.ProcDir, d.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(w.ProcDir, d.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if want[ino] {
				if _, ok := out[ino]; !ok {
					out[ino] = [2]string{d.Name(), w.procName(d.Name())}
				}
			}
		}
		if len(out) == len(want) {
			break
		}
	}
	return out
}

// rawListeners reports a program outside rawAllowed holding a raw packet socket (/proc/net/packet; its owner looked up only
// for a socket not seen before). A socket whose owner cannot be seen (another user's, without the rights) is passed over.
func (w *Watcher) rawListeners() []detect.Event {
	b, err := os.ReadFile(filepath.Join(w.ProcDir, "net", "packet"))
	if err != nil {
		return nil
	}
	now := map[string]bool{}
	want := map[string]bool{}
	proto := map[string]string{}
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 9 || f[8] == "0" {
			continue
		}
		now[f[8]] = true
		if !w.rawSeen[f[8]] {
			want[f[8]] = true
			proto[f[8]] = f[3]
		}
	}
	var out []detect.Event
	if len(want) > 0 {
		owners := w.socketOwners(want)
		for _, ino := range sortedKeys(want) {
			o, ok := owners[ino]
			if !ok || o[1] == "" || rawAllowed[o[1]] {
				continue
			}
			out = append(out, event(fmt.Sprintf("%s (pid %s) reads raw network packets", o[1], o[0]),
				map[string]string{"provider": o[1], "ra_kind": "kernel", "signal": "raw-listener", "program": o[1], "pid": o[0],
					"proto": proto[ino]}))
		}
	}
	w.rawSeen = now
	return out
}

// socketShells reports a shell whose input (fd 0) is a TCP or UDP socket: a reverse shell. A Unix socket (a service's
// journal stream, a terminal multiplexer) is not the network and is passed over.
func (w *Watcher) socketShells() []detect.Event {
	dirs, err := os.ReadDir(w.ProcDir)
	if err != nil {
		return nil
	}
	now := map[string]bool{}
	var inet map[string]string
	var out []detect.Event
	for _, d := range dirs {
		pid := d.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		comm := w.procName(pid)
		if !shells[comm] {
			continue
		}
		link, err := os.Readlink(filepath.Join(w.ProcDir, pid, "fd", "0"))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		ino := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		key := pid + "|" + ino
		now[key] = true
		if w.shellSeen[key] {
			continue
		}
		if inet == nil {
			inet = w.inetSockets()
		}
		conn, ok := inet[ino]
		if !ok {
			continue
		}
		out = append(out, event(fmt.Sprintf("the shell %s (pid %s) takes its input from a network connection (%s)", comm, pid, conn),
			map[string]string{"provider": comm, "ra_kind": "kernel", "signal": "socket-shell", "program": comm, "pid": pid,
				"connection": conn}))
	}
	w.shellSeen = now
	return out
}

// inetSockets are the TCP and UDP sockets by inode, each as "tcp LOCAL -> REMOTE".
func (w *Watcher) inetSockets() map[string]string {
	out := map[string]string{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open(filepath.Join(w.ProcDir, "net", name))
		if err != nil {
			continue
		}
		entries, _ := netsource.ParseProcNetTCP(f)
		f.Close()
		for _, e := range entries {
			out[strconv.FormatUint(e.Inode, 10)] = fmt.Sprintf("%s %s -> %s", strings.TrimSuffix(name, "6"),
				net.JoinHostPort(e.LocalIP.String(), strconv.Itoa(e.LocalPort)), net.JoinHostPort(e.RemoteIP.String(), strconv.Itoa(e.RemotePort)))
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (w *Watcher) Poll() []detect.Event {
	out := append(w.packages(), w.interfaces()...)
	out = append(out, w.modules()...)
	out = append(out, w.rawListeners()...)
	out = append(out, w.socketShells()...)
	w.started = true
	return out
}

func (w *Watcher) Run(ctx context.Context, interval time.Duration, emit func(detect.Event)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, e := range w.Poll() {
			emit(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
