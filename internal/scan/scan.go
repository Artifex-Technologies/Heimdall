// Package scan is Heimdall's file malware-scanning engine: it decides which files to look at (folders, an exclusion list, a
// size limit, a remembered state so unchanged files are skipped) and hands each to a Scanner. The Scanner is ClamAV
// (clamdscan or clamscan, which must be installed separately; without it everything reports "unavailable" and nothing breaks).
//
// It runs as whichever user starts it: a user's own Downloads folder is only readable by that user, so the scan of a home folder is
// meant to be run by a per-user service or on demand (`heimdalld scan-files`), not by the system Heimdall service. Nothing here
// moves or deletes a file; it only reports. Quarantine and the "restore / delete / always allow" choice belong to the desktop.
package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Result is the outcome for one file.
type Result struct {
	Path      string `json:"path"`
	Infected  bool   `json:"infected"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Scanner looks at one file.
type Scanner interface {
	Name() string
	Available() bool
	ScanFile(ctx context.Context, path string) (Result, error)
}

// BatchScanner is an optional extension: scan many files in one go.
type BatchScanner interface {
	ScanBatch(ctx context.Context, paths []string) []Result
}

// ---- ClamAV

// ClamAV runs clamdscan (when the daemon's socket exists) or clamscan.
type ClamAV struct {
	bin string
	// extra arguments, for tests
	args []string
}

// clamdSockets are where clamd listens on Arch and Debian.
var clamdSockets = []string{"/run/clamav/clamd.ctl", "/run/clamav/clamd.sock", "/var/run/clamav/clamd.ctl"}

// NewClamAV finds a ClamAV command line tool on PATH: clamdscan when the clamd daemon is running (fast: the signatures stay loaded),
// otherwise clamscan (loads the signatures on every call: it works without a daemon but each run starts slowly).
func NewClamAV() *ClamAV {
	if p, err := exec.LookPath("clamdscan"); err == nil {
		for _, sock := range clamdSockets {
			if _, err := os.Stat(sock); err == nil {
				return &ClamAV{bin: p}
			}
		}
	}
	if p, err := exec.LookPath("clamscan"); err == nil {
		return &ClamAV{bin: p}
	}
	return &ClamAV{}
}

func (c *ClamAV) Name() string    { return "clamav" }
func (c *ClamAV) Available() bool { return c.bin != "" }

func (c *ClamAV) ScanFile(ctx context.Context, path string) (Result, error) {
	if !c.Available() {
		return Result{Path: path}, errors.New("scan: ClamAV is not installed")
	}
	args := append([]string{"--no-summary"}, c.args...)
	if strings.HasSuffix(c.bin, "clamdscan") {
		args = append(args, "--fdpass")
	}
	args = append(args, "--", path)
	out, err := exec.CommandContext(ctx, c.bin, args...).CombinedOutput()
	res := ParseClamOutput(path, string(out))
	if res.Infected || res.Error == "" && err == nil {
		return res, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 { // 1 = something found
		return res, nil
	}
	if res.Error == "" {
		res.Error = strings.TrimSpace(string(out))
	}
	return res, fmt.Errorf("scan: clamav failed on %s: %s", path, res.Error)
}

// ScanBatch scans several files with ONE ClamAV run (clamscan loads its signature database on every start, several seconds, so one
// run per file would be far too slow for a folder). Results come back in the order of paths; a file ClamAV did not mention is an error.
func (c *ClamAV) ScanBatch(ctx context.Context, paths []string) []Result {
	res := make([]Result, len(paths))
	for i, p := range paths {
		res[i] = Result{Path: p, Error: "not reported by ClamAV"}
	}
	if !c.Available() || len(paths) == 0 {
		for i := range res {
			res[i].Error = "ClamAV is not installed"
		}
		return res
	}
	index := make(map[string]int, len(paths))
	for i, p := range paths {
		index[p] = i
	}
	args := append([]string{"--no-summary"}, c.args...)
	if strings.HasSuffix(c.bin, "clamdscan") {
		args = append(args, "--fdpass")
	}
	args = append(args, "--")
	args = append(args, paths...)
	out, _ := exec.CommandContext(ctx, c.bin, args...).CombinedOutput() // exit status 1 just means "found something"
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		i := strings.LastIndex(line, ": ")
		if i < 0 {
			continue
		}
		idx, ok := index[line[:i]]
		if !ok {
			continue
		}
		verdict := line[i+2:]
		switch {
		case verdict == "OK":
			res[idx] = Result{Path: paths[idx]}
		case strings.HasSuffix(verdict, " FOUND"):
			res[idx] = Result{Path: paths[idx], Infected: true, Signature: strings.TrimSuffix(verdict, " FOUND")}
		case strings.HasSuffix(verdict, " ERROR"):
			res[idx] = Result{Path: paths[idx], Error: line}
		}
	}
	return res
}

// ParseClamOutput reads clamscan/clamdscan's "path: Signature FOUND" / "path: OK" / "path: reason ERROR" line.
func ParseClamOutput(path, out string) Result {
	res := Result{Path: path}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasSuffix(line, " FOUND"):
			res.Infected = true
			if i := strings.LastIndex(line, ": "); i >= 0 {
				res.Signature = strings.TrimSuffix(line[i+2:], " FOUND")
			}
		case strings.HasSuffix(line, " ERROR"):
			res.Error = line
		}
	}
	return res
}

// ---- which files

// Excluder says which paths are never scanned: a path prefix (a folder or one file) or a glob (`*.iso`, `*/node_modules/*`).
type Excluder struct{ Patterns []string }

func (e Excluder) Match(path string) bool {
	for _, p := range e.Patterns {
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, "*?[") {
			if ok, _ := filepath.Match(p, path); ok {
				return true
			}
			if ok, _ := filepath.Match(p, filepath.Base(path)); ok {
				return true
			}
			continue
		}
		clean := filepath.Clean(p)
		if path == clean || strings.HasPrefix(path, clean+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// State remembers what was already scanned (path -> size and modification time), so unchanged files are skipped next time.
type State struct {
	path  string
	Files map[string]stamp `json:"files"`
	// Signatures is a stamp of the signatures the files were scanned with; when it changes (Heimdall learned something), every file
	// is scanned again, so copies that arrived before are caught too.
	Signatures string `json:"signatures,omitempty"`
}

// UseSignatures sets the stamp of the signatures in use, forgetting every file when it differs from the one they were scanned with.
func (s *State) UseSignatures(sig string) {
	if s.Signatures != sig {
		s.Files = map[string]stamp{}
		s.Signatures = sig
	}
}

// FileStamp is a stamp of a signature file (size and modification time; "" when it is not there).
func FileStamp(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
}

type stamp struct {
	Size  int64 `json:"size"`
	MTime int64 `json:"mtime"`
}

func LoadState(path string) *State {
	st := &State{path: path, Files: map[string]stamp{}}
	if path == "" {
		return st
	}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, st)
		if st.Files == nil {
			st.Files = map[string]stamp{}
		}
	}
	return st
}

func (s *State) Save() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *State) unchanged(path string, info fs.FileInfo) bool {
	st, ok := s.Files[path]
	return ok && st.Size == info.Size() && st.MTime == info.ModTime().UnixNano()
}

func (s *State) record(path string, info fs.FileInfo) {
	s.Files[path] = stamp{Size: info.Size(), MTime: info.ModTime().UnixNano()}
}

// Options for Collect.
type Options struct {
	Exclude  Excluder
	MaxBytes int64 // files larger than this are skipped (0 = no limit)
	State    *State
}

// Collect walks the roots and returns the regular files that should be scanned, sorted. Symlinks are not followed.
func Collect(roots []string, o Options) ([]string, error) {
	var files []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable: skip it
			}
			if o.Exclude.Match(p) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if o.MaxBytes > 0 && info.Size() > o.MaxBytes {
				return nil
			}
			if o.State != nil && o.State.unchanged(p, info) {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			return files, err
		}
	}
	sort.Strings(files)
	return files, nil
}

// Run scans the files with the scanner and returns every result. A file that scanned without an error is recorded in the state
// (an infected one too: it is reported once, not on every run); a file that could not be scanned is left out of the state so it
// is tried again.
func Run(ctx context.Context, sc Scanner, files []string, st *State) []Result {
	var out []Result
	if b, ok := sc.(BatchScanner); ok {
		const chunk = 200
		for i := 0; i < len(files) && ctx.Err() == nil; i += chunk {
			end := i + chunk
			if end > len(files) {
				end = len(files)
			}
			for _, r := range b.ScanBatch(ctx, files[i:end]) {
				if r.Error == "" && st != nil {
					if info, e := os.Stat(r.Path); e == nil {
						st.record(r.Path, info)
					}
				}
				out = append(out, r)
			}
		}
		return out
	}
	for _, f := range files {
		if ctx.Err() != nil {
			break
		}
		res, err := sc.ScanFile(ctx, f)
		if err != nil {
			if res.Error == "" {
				res.Error = err.Error()
			}
			out = append(out, res)
			continue
		}
		if st != nil {
			if info, e := os.Stat(f); e == nil {
				st.record(f, info)
			}
		}
		out = append(out, res)
	}
	return out
}

// Elapsed is a helper for callers that report how long a run took.
func Elapsed(start time.Time) string { return time.Since(start).Round(time.Millisecond).String() }
