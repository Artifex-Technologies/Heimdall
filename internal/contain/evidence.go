package contain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/immunity"
)

// EvidenceDir holds what was saved before each containment (root-only): what was running, what it talked to, the recent logs and
// sessions, and copies of the files that were not as approved. Killing a process destroys exactly what is needed to learn what
// happened, so this comes first; it takes a few seconds and is capped in size.
const EvidenceDir = "/var/lib/heimdall-evidence"

const (
	maxSessionFiles = 40
	maxCopyBytes    = 4 << 20 // per file
	maxTotalBytes   = 256 << 20
)

// proc is one process as /proc shows it.
type proc struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	UID     string `json:"uid"`
	Comm    string `json:"comm"`
	Exe     string `json:"exe"`
	ExeHash string `json:"exe_sha256,omitempty"`
	Cmdline string `json:"cmdline"`
	Cwd     string `json:"cwd"`
	Started string `json:"start_ticks"`
}

func readProc(pid int, hash bool) (proc, bool) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return proc{}, false
	}
	p := proc{PID: pid}
	s := string(stat)
	if i := strings.LastIndexByte(s, ')'); i > 0 {
		f := strings.Fields(s[i+1:])
		if len(f) > 19 {
			p.PPID, _ = strconv.Atoi(f[1])
			p.Started = f[19]
		}
	}
	comm, _ := os.ReadFile(filepath.Join(base, "comm"))
	p.Comm = strings.TrimSpace(string(comm))
	p.Exe, _ = os.Readlink(filepath.Join(base, "exe"))
	p.Cwd, _ = os.Readlink(filepath.Join(base, "cwd"))
	cl, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cl), "\x00", " "))
	if st, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, l := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(l, "Uid:") {
				if f := strings.Fields(l); len(f) > 1 {
					p.UID = f[1]
				}
			}
		}
	}
	if hash && p.Exe != "" {
		// through /proc/PID/exe: the program that is running, even when its file was replaced or deleted
		if f, err := os.Open(filepath.Join(base, "exe")); err == nil {
			h := sha256.New()
			if _, err := io.Copy(h, io.LimitReader(f, 512<<20)); err == nil {
				p.ExeHash = hex.EncodeToString(h.Sum(nil))
			}
			f.Close()
		}
	}
	return p, true
}

// evidence is one collection in progress.
type evidence struct {
	dir   string
	total int64
	notes []string
}

func (e *evidence) write(name string, b []byte) {
	if e.total+int64(len(b)) > maxTotalBytes {
		e.notes = append(e.notes, name+": skipped (the size cap was reached)")
		return
	}
	p := filepath.Join(e.dir, name)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		e.notes = append(e.notes, name+": "+err.Error())
		return
	}
	e.total += int64(len(b))
}

func (e *evidence) json(name string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	e.write(name, append(b, '\n'))
}

func (e *evidence) command(name string, args ...string) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil && len(out) == 0 {
		e.notes = append(e.notes, name+": "+err.Error())
		return
	}
	if len(out) > maxCopyBytes {
		out = out[:maxCopyBytes]
	}
	e.write(name, out)
}

// copyFile keeps a copy under files/ with its full path, and its hash in the index.
func (e *evidence) copyFile(path string, index map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCopyBytes+1))
	if err != nil {
		return
	}
	sum := sha256.Sum256(b)
	index[path] = hex.EncodeToString(sum[:])
	if len(b) > maxCopyBytes {
		index[path] += " (larger than 4 MiB: only the first 4 MiB kept)"
		b = b[:maxCopyBytes]
	}
	e.write(filepath.Join("files", strings.TrimPrefix(path, "/")), b)
}

// Collect saves the evidence (as root) and returns the folder. Suspicious files are the ones the trust list does not approve
// (changed, or new in a watched folder); sessions are the newest in each session folder given.
func (s Real) Collect(reason string) (string, error) {
	root := s.EvidenceDir
	if root == "" {
		root = EvidenceDir
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(root, 0o700)
	dir := filepath.Join(root, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	e := &evidence{dir: dir}
	e.json("reason.json", map[string]any{"time": time.Now().UTC(), "reason": reason})

	// what was running: everything (short), and Sarina's processes with their program's hash
	var all, hers []proc
	herPIDs := sarinaProcs()
	entries, _ := os.ReadDir("/proc")
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		_, isHers := herPIDs[pid]
		if p, ok := readProc(pid, isHers); ok {
			all = append(all, p)
			if isHers {
				hers = append(hers, p)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].PID < all[j].PID })
	e.json("processes.json", all)
	e.json("sarina-processes.json", hers)
	for _, p := range hers {
		base := filepath.Join("/proc", strconv.Itoa(p.PID))
		maps, _ := os.ReadFile(filepath.Join(base, "maps"))
		e.write(fmt.Sprintf("sarina-%d/maps", p.PID), maps)
		env, _ := os.ReadFile(filepath.Join(base, "environ"))
		e.write(fmt.Sprintf("sarina-%d/environ", p.PID), redactEnv(env))
		if fds, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
			var open []string
			for _, fd := range fds {
				if t, err := os.Readlink(filepath.Join(base, "fd", fd.Name())); err == nil {
					open = append(open, fd.Name()+" -> "+t)
				}
			}
			e.write(fmt.Sprintf("sarina-%d/open-files", p.PID), []byte(strings.Join(open, "\n")+"\n"))
		}
	}

	// what talked to what, what is on the graphics card, what the model server holds, the last hour of logs
	e.command("connections.txt", "ss", "-tupanoe")
	e.command("graphics.txt", "nvidia-smi", "--query-compute-apps=pid,process_name,used_memory", "--format=csv")
	e.json("models-loaded.json", s.ModelsLoaded())
	e.command("journal.txt", "journalctl", "--since", "-1h", "--no-pager", "-o", "short-iso", "-n", "20000")

	// the files that decide how she behaves and are not as approved
	index := map[string]string{}
	var suspects []string
	for _, p := range hers {
		// the program she ran, unless it is an installed package's (/usr): a replaced or planted program is a sample worth keeping
		if p.Exe != "" && !strings.HasPrefix(p.Exe, "/usr/") {
			suspects = append(suspects, filepath.Join("/proc", strconv.Itoa(p.PID), "exe")+"\x00"+p.Exe)
		}
	}
	if _, err := s.Trust.Load(); err == nil {
		for _, f := range s.Trust.Unapproved() {
			e.copyFile(f, index)
			suspects = append(suspects, f)
		}
	} else {
		e.notes = append(e.notes, "no signed list (heimdalld trust init): her behaviour files could not be compared")
	}
	// her newest sessions: what she was asked and what she did
	for _, d := range s.SessionDirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		type mf struct {
			p string
			t time.Time
		}
		var files []mf
		for _, ent := range ents {
			if info, err := ent.Info(); err == nil && info.Mode().IsRegular() {
				files = append(files, mf{filepath.Join(d, ent.Name()), info.ModTime()})
			}
		}
		sort.Slice(files, func(i, j int) bool { return files[i].t.After(files[j].t) })
		for i := 0; i < len(files) && i < maxSessionFiles; i++ {
			e.copyFile(files[i].p, index)
		}
	}
	e.json("files-index.json", index)
	e.notes = append(e.notes, keepSuspects(s.Immunity, suspects, reason)...)
	e.json("notes.json", e.notes)
	return dir, nil
}

// redactEnv keeps the names of the environment and hides values that look like secrets.
func redactEnv(env []byte) []byte {
	var out []string
	for _, kv := range strings.Split(string(env), "\x00") {
		if kv == "" {
			continue
		}
		k, _, _ := strings.Cut(kv, "=")
		u := strings.ToUpper(k)
		if strings.Contains(u, "TOKEN") || strings.Contains(u, "KEY") || strings.Contains(u, "SECRET") || strings.Contains(u, "PASS") {
			kv = k + "=[hidden]"
		}
		out = append(out, kv)
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// keepSuspects puts what the evidence found suspicious into Heimdall's immunity store as suspects: kept for the owner to confirm (or
// for an analysis), never fingerprinted by itself.
func keepSuspects(st *immunity.Store, paths []string, reason string) []string {
	if st == nil {
		return nil
	}
	var notes []string
	for _, p := range paths {
		// "read-from\x00shown-as": a running program is read through /proc/PID/exe (the program that ran, even if its file was
		// replaced since) and kept under its real path
		from, shown, ok := strings.Cut(p, "\x00")
		if !ok {
			shown = from
		}
		if en, err := st.KeepAs(from, shown, "found during a containment: "+reason, "containment"); err != nil {
			notes = append(notes, "not kept as a suspect: "+err.Error())
		} else {
			notes = append(notes, fmt.Sprintf("kept as a suspect: %s (%s) %s; sudo heimdalld immunity confirm %s if it is malware", shown, en.Kind, en.SHA256, en.SHA256[:12]))
		}
	}
	return notes
}
