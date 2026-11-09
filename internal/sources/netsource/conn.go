package netsource

import (
	"encoding/json"
	"fmt"
	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
)

// ConnWatcher records which process holds each established TCP connection to a
// non-loopback address. It reads /proc/net/tcp{,6} for the sockets and
// /proc/<pid>/fd to find the owner of each one; it never captures packets and
// never sees contents. Seeing other users' processes needs CAP_SYS_PTRACE (see
// packaging/heimdall-connwatch.conf.example); without it the connection is still
// reported, with the process shown as "unknown".
//
// A (process, remote address, port) triple is reported once, the first time it is
// seen, and remembered in a state file. The very first run, with no state file,
// only learns: it records what is already connected and marks those events as
// "learning" so a detector does not raise an alert for each of them.
//
// The owner of a socket is looked for once: /proc/<pid>/fd is walked only when a
// socket appears that has not been looked for (readlink of every open file of every
// process every 10 s was most of the watcher's cost). The walk starts with the
// processes that already hold connections and stops when every new socket is found.
type ConnWatcher struct {
	// RemoteAccess, when set, tags connections held by a remote-access tool from the catalog (ra_provider).
	RemoteAccess *remoteaccess.Identifier
	procRoot     string
	tcpPaths     []string
	statePath    string
	policyPath   string
	known        map[string]bool
	loaded       bool
	learning     bool
	// Origins, when set, names the country and network of each new destination (offline; see internal/ipintel).
	Origins *ipintel.Resolver
	// Threats, when set, are the threat lists each new destination is checked against (offline).
	Threats *ipintel.Lists
	// owned is the owner of each established connection's socket, by inode; nil when the walk did not find one (a process
	// Heimdall may not look into). A socket's entry goes when its connection does.
	owned map[uint64]*owner
	// scanned counts the processes whose open files were read (tests and benchmarks look at it).
	scanned int
}

func NewConnWatcher(statePath, policyPath string) *ConnWatcher {
	return newConnWatcher("/proc", statePath, policyPath)
}

func newConnWatcher(procRoot, statePath, policyPath string) *ConnWatcher {
	return &ConnWatcher{
		procRoot:   procRoot,
		tcpPaths:   []string{filepath.Join(procRoot, "net/tcp"), filepath.Join(procRoot, "net/tcp6")},
		statePath:  statePath,
		policyPath: policyPath,
		known:      map[string]bool{},
	}
}

var appSlice = regexp.MustCompile(`lapp_([^/]+)\.slice`)

func sanitizeApp(id string) string {
	return regexp.MustCompile(`[^A-Za-z0-9._+-]`).ReplaceAllString(id, "_")
}

func (w *ConnWatcher) loadState() {
	w.loaded = true
	raw, err := os.ReadFile(w.statePath)
	if err != nil {
		w.learning = true // nothing known yet: learn, do not alert
		return
	}
	var st struct {
		Known []string `json:"known"`
	}
	if json.Unmarshal(raw, &st) == nil {
		for _, k := range st.Known {
			w.known[k] = true
		}
	}
}

func (w *ConnWatcher) saveState() error {
	if w.statePath == "" {
		return nil
	}
	keys := make([]string, 0, len(w.known))
	for k := range w.known {
		keys = append(keys, k)
	}
	raw, _ := json.Marshal(map[string]any{"known": keys})
	tmp := w.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.statePath)
}

// blockedApps returns the sanitized ids of apps whose network the owner switched off.
func (w *ConnWatcher) blockedApps() map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(w.policyPath)
	if err != nil {
		return out
	}
	var d struct {
		Rules map[string]map[string]string `json:"rules"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return out
	}
	for _, apps := range d.Rules {
		for app, mode := range apps {
			if mode == "block" {
				out[sanitizeApp(app)] = true
			}
		}
	}
	return out
}

type owner struct {
	pid    int
	comm   string
	app    string
	exe    string
	script string // the file an interpreter runs (scriptOf)
	agent  string // the AI agent among its ancestors (agentAncestor)
}

// resolve returns the owner of each socket inode in want. /proc is walked only for sockets not looked for before.
func (w *ConnWatcher) resolve(want map[uint64]bool) map[uint64]owner {
	if w.owned == nil {
		w.owned = map[uint64]*owner{}
	}
	unseen := map[uint64]bool{}
	for ino := range want {
		if _, ok := w.owned[ino]; !ok {
			unseen[ino] = true
		}
	}
	if len(unseen) > 0 {
		// the processes holding connections now are the likeliest to have opened the new ones, the busiest (a browser) first
		count := map[int]int{}
		for _, o := range w.owned {
			if o != nil {
				count[o.pid]++
			}
		}
		hot := make([]int, 0, len(count))
		for pid := range count {
			hot = append(hot, pid)
		}
		sort.Slice(hot, func(i, j int) bool {
			if count[hot[i]] != count[hot[j]] {
				return count[hot[i]] > count[hot[j]]
			}
			return hot[i] < hot[j]
		})
		found := w.owners(unseen, hot)
		for ino := range unseen {
			if o, ok := found[ino]; ok {
				w.owned[ino] = &o
			} else {
				w.owned[ino] = nil
			}
		}
	}
	out := make(map[uint64]owner, len(want))
	for ino, o := range w.owned {
		switch {
		case !want[ino]:
			delete(w.owned, ino) // the connection is gone
		case o != nil:
			out[ino] = *o
		}
	}
	return out
}

// owners maps socket inodes to the process holding them, looking at the processes in hot first and stopping once every
// inode in want is found. A socket two processes share (after a fork) is named after the first one found.
func (w *ConnWatcher) owners(want map[uint64]bool, hot []int) map[uint64]owner {
	out := map[uint64]owner{}
	done := map[int]bool{}
	for _, pid := range hot {
		if !done[pid] {
			done[pid] = true
			if w.socketsOf(pid, want, out) {
				return out
			}
		}
	}
	dirs, err := os.ReadDir(w.procRoot)
	if err != nil {
		return out
	}
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || done[pid] {
			continue
		}
		if w.socketsOf(pid, want, out) {
			return out
		}
	}
	return out
}

// socketsOf records in out the wanted sockets process pid holds, and reports whether every wanted socket is now found.
func (w *ConnWatcher) socketsOf(pid int, want map[uint64]bool, out map[uint64]owner) bool {
	name := strconv.Itoa(pid)
	fdDir := filepath.Join(w.procRoot, name, "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	w.scanned++
	var o *owner
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
		if err != nil || !want[ino] {
			continue
		}
		if _, found := out[ino]; found {
			continue
		}
		if o == nil {
			comm, _ := os.ReadFile(filepath.Join(w.procRoot, name, "comm"))
			cg, _ := os.ReadFile(filepath.Join(w.procRoot, name, "cgroup"))
			exe, _ := os.Readlink(filepath.Join(w.procRoot, name, "exe"))
			o = &owner{pid: pid, comm: strings.TrimSpace(string(comm)), exe: exe, agent: agentAncestor(w.procRoot, pid)}
			cwd, _ := os.Readlink(filepath.Join(w.procRoot, name, "cwd"))
			o.script = scriptOf(exe, argvOf(w.procRoot, pid), cwd)
			if m := appSlice.FindStringSubmatch(string(cg)); m != nil {
				o.app = m[1]
			}
		}
		out[ino] = *o
		if len(out) == len(want) {
			return true
		}
	}
	return false
}

// Poll returns an event for every connection destination not seen before.
func (w *ConnWatcher) Poll() ([]detect.Event, error) {
	all, err := readTables(w.tcpPaths)
	if err != nil {
		return nil, err
	}
	return w.observe(all)
}

// observe is Poll on one read of the socket tables (Tables shares a read between the watchers).
func (w *ConnWatcher) observe(all []socketEntry) ([]detect.Event, error) {
	if !w.loaded {
		w.loadState()
	}
	var entries []socketEntry
	for _, e := range all {
		if e.State == tcpEstablished && !e.RemoteIP.IsLoopback() && !e.RemoteIP.IsUnspecified() {
			entries = append(entries, e)
		}
	}
	want := map[uint64]bool{}
	for _, e := range entries {
		want[e.Inode] = true
	}
	owners := w.resolve(want)
	blocked := w.blockedApps()

	now := time.Now()
	var events []detect.Event
	fresh := false
	for _, e := range entries {
		o, ok := owners[e.Inode]
		proc := "unknown"
		if ok && o.comm != "" {
			proc = o.comm
		}
		key := fmt.Sprintf("%s|%s|%d", proc, e.RemoteIP, e.RemotePort)
		if w.known[key] {
			continue
		}
		w.known[key] = true
		fresh = true
		f := map[string]string{
			"process":     proc,
			"pid":         strconv.Itoa(o.pid),
			"app":         o.app,
			"uid":         strconv.Itoa(e.UID),
			"remote_addr": e.RemoteIP.String(),
			"remote_port": strconv.Itoa(e.RemotePort),
			"local_port":  strconv.Itoa(e.LocalPort),
		}
		// for the tool rules: which program file (or script) it is, and whether an AI agent started it
		for k, v := range map[string]string{"exe": o.exe, "script": o.script, "agent": o.agent} {
			if v != "" {
				f[k] = v
			}
		}
		text := fmt.Sprintf("%s (pid %d) connected to %s:%d", proc, o.pid, e.RemoteIP, e.RemotePort)
		if w.Origins != nil {
			og := w.Origins.Lookup(e.RemoteIP)
			for k, v := range og.Fields("remote_") {
				f[k] = v
			}
			f["remote_origin"] = og.String()
			text += " (" + og.String() + ")"
		}
		if l := w.Threats.Match(e.RemoteIP); len(l) > 0 {
			f["remote_listed"] = strings.Join(l, ",")
			text += " [on threat lists: " + f["remote_listed"] + "]"
		}
		if w.learning {
			f["learning"] = "1"
		}
		if o.app != "" && blocked[o.app] {
			f["blocked"] = "1"
		}
		// a remote-access tool (by its program, or a renamed Go program by its build info): the remote-access detector judges it
		if w.RemoteAccess != nil && ok {
			if p, sig := w.RemoteAccess.Identify(o.exe, o.comm); p != nil {
				f["ra_provider"], f["provider_name"], f["ra_kind"], f["ra_signal"], f["exe"] = p.ID, p.Name, p.Kind, sig, o.exe
			}
		}
		events = append(events, detect.Event{
			Source: "host-network", Time: now, Kind: "new_connection",
			Text:   text,
			Fields: f,
		})
	}
	w.learning = false
	if fresh {
		if err := w.saveState(); err != nil {
			return events, err
		}
	}
	return events, nil
}
