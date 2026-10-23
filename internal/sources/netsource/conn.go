package netsource

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
type ConnWatcher struct {
	procRoot   string
	tcpPaths   []string
	statePath  string
	policyPath string
	known      map[string]bool
	loaded     bool
	learning   bool
	// Origins, when set, names the country and network of each new destination (offline; see internal/ipintel).
	Origins *ipintel.Resolver
	// Threats, when set, are the threat lists each new destination is checked against (offline).
	Threats *ipintel.Lists
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
	pid  int
	comm string
	app  string
}

// owners maps socket inodes to the process holding them.
func (w *ConnWatcher) owners(want map[uint64]bool) map[uint64]owner {
	out := map[uint64]owner{}
	dirs, err := os.ReadDir(w.procRoot)
	if err != nil {
		return out
	}
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(w.procRoot, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
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
			if o == nil {
				comm, _ := os.ReadFile(filepath.Join(w.procRoot, d.Name(), "comm"))
				cg, _ := os.ReadFile(filepath.Join(w.procRoot, d.Name(), "cgroup"))
				o = &owner{pid: pid, comm: strings.TrimSpace(string(comm))}
				if m := appSlice.FindStringSubmatch(string(cg)); m != nil {
					o.app = m[1]
				}
			}
			out[ino] = *o
		}
	}
	return out
}

// Poll returns an event for every connection destination not seen before.
func (w *ConnWatcher) Poll() ([]detect.Event, error) {
	if !w.loaded {
		w.loadState()
	}
	var entries []socketEntry
	opened := 0
	var lastErr error
	for _, path := range w.tcpPaths {
		f, err := os.Open(path)
		if err != nil {
			lastErr = err
			continue
		}
		opened++
		parsed, _ := ParseProcNetTCP(f)
		f.Close()
		for _, e := range parsed {
			if e.State == tcpEstablished && !e.RemoteIP.IsLoopback() && !e.RemoteIP.IsUnspecified() {
				entries = append(entries, e)
			}
		}
	}
	if opened == 0 {
		return nil, lastErr
	}
	want := map[uint64]bool{}
	for _, e := range entries {
		want[e.Inode] = true
	}
	owners := w.owners(want)
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

func (w *ConnWatcher) Run(ctx context.Context, interval time.Duration, onUnavailable func(error), onErr func(error), emit func(detect.Event)) {
	step := func() bool {
		events, err := w.Poll()
		if err != nil {
			if os.IsNotExist(err) {
				if onUnavailable != nil {
					onUnavailable(err)
				}
				return false
			}
			if onErr != nil {
				onErr(err)
			}
		}
		for _, e := range events {
			emit(e)
		}
		return true
	}
	if !step() {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			step()
		}
	}
}
