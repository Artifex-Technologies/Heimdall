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

// ---- ClamAV

// ClamAV runs clamdscan (when the daemon's socket exists) or clamscan.
type ClamAV struct {
	bin string
	// extra arguments, for tests
	args []string
}

// NewClamAV finds a ClamAV command line tool on PATH.
func NewClamAV() *ClamAV {
	for _, name := range []string{"clamdscan", "clamscan"} {
		if p, err := exec.LookPath(name); err == nil {
			return &ClamAV{bin: p}
		}
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
