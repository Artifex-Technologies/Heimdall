package hostsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// FileBaseline is one watched path's last-known state. Exported so it
// round-trips through encoding/json for on-disk persistence (see
// NewFIMWatcherWithState).
type FileBaseline struct {
	ModTime time.Time `json:"mod_time"`
	Size    int64     `json:"size"`
	Hash    string    `json:"hash"`
}

// FIMWatcher polls a fixed, explicit list of paths for content changes --
// deliberately not a whole-filesystem scan. Heimdall's file-integrity job is
// "did one of the specific files this ecosystem's tooling depends on
// change unexpectedly" (a CLAUDE.md, a PKGBUILD, a systemd unit), not a
// general-purpose FIM product; see docs/ARCHITECTURE.md's Phase 2 section.
//
// Wazuh's syscheck is the reference for the efficiency technique used
// here: a cheap mtime+size comparison decides whether a file needs
// rehashing at all, so an unpolled, unchanged file -- the common case on
// every poll -- costs one os.Stat and nothing else. Only a path whose
// mtime or size actually moved gets read and hashed.
type FIMWatcher struct {
	paths     []string
	statePath string
	baselines map[string]FileBaseline
	loaded    map[string]FileBaseline // the saved state, until keepLoaded sorts it
	// Folders watched as a whole (the AI agents' skills and agents folders): a file that appears in one after its first look is
	// reported too (file_created), since that is how a planted skill arrives.
	dirs []string
	// graced paths (the agents' behaviour files, see WithTrust) are reported only after grace has passed, so a change approved by
	// signing it right after making it is judged against the signed list, not raised in the minute in between.
	graced  map[string]bool
	grace   time.Duration
	pending map[string]pendingChange
	now     func() time.Time
}

type pendingChange struct {
	seen  time.Time
	event detect.Event
}

// dirMarker is the state entry that says a folder has had its first (silent) look.
const dirMarker = "dir:"

// WithTrust adds the agents' behaviour files and folders (trust.WatchList) to the watch, judged after grace.
func (w *FIMWatcher) WithTrust(files, dirs []string, grace time.Duration) *FIMWatcher {
	w.graced = map[string]bool{}
	for _, f := range files {
		w.paths = append(w.paths, f)
		w.graced[f] = true
	}
	w.dirs = append(w.dirs, dirs...)
	w.grace = grace
	w.keepLoaded()
	return w
}

func (w *FIMWatcher) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

func (w *FIMWatcher) underDir(path string) bool {
	for _, d := range w.dirs {
		if strings.HasPrefix(path, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// dirFiles lists the regular files under the watched folders (symbolic links are not followed; at most 5000 a folder).
func (w *FIMWatcher) dirFiles() map[string]bool {
	out := map[string]bool{}
	for _, d := range w.dirs {
		n := 0
		_ = filepath.WalkDir(d, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.Type().IsRegular() && n < 5000 {
				out[path] = true
				n++
			}
			return nil
		})
	}
	return out
}

// NewFIMWatcher holds baselines in memory only -- state is lost when the
// process exits. Fine for tests; NewFIMWatcherWithState is what heimdalld
// actually uses, because an in-memory-only baseline means every process
// restart silently re-establishes a fresh baseline for every watched file,
// and a file tampered with in the exact window around that restart would
// never be reported.
func NewFIMWatcher(paths []string) *FIMWatcher {
	return &FIMWatcher{paths: paths, baselines: make(map[string]FileBaseline)}
}

// NewFIMWatcherWithState behaves like NewFIMWatcher but loads any existing
// baseline snapshot from statePath (if present) and Poll saves the updated
// snapshot back to it every call, so integrity state survives a heimdalld
// restart. A missing or unparseable state file is treated the same as "no
// state yet" -- the worst case is one extra silent baseline-establishing
// poll, not a startup failure over what is disposable cache, not a source
// of truth.
func NewFIMWatcherWithState(paths []string, statePath string) *FIMWatcher {
	w := NewFIMWatcher(paths)
	w.statePath = statePath
	if statePath == "" {
		return w
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return w
	}
	var loaded map[string]FileBaseline
	if json.Unmarshal(raw, &loaded) != nil {
		return w
	}
	w.loaded = loaded
	w.keepLoaded()
	return w
}

// keepLoaded drops saved entries for paths no longer watched (a file list, a folder, a folder's marker). Called once the watch is
// complete (WithTrust may add to it after the constructor).
func (w *FIMWatcher) keepLoaded() {
	if w.loaded == nil {
		return
	}
	watched := make(map[string]bool, len(w.paths))
	for _, p := range w.paths {
		watched[p] = true
	}
	for _, d := range w.dirs {
		watched[dirMarker+d] = true
	}
	for path, b := range w.loaded {
		if watched[path] || w.underDir(path) {
			w.baselines[path] = b
		}
	}
}

// Poll checks every configured path once. A path seen for the first time
// establishes a silent baseline (no Event -- there is nothing to compare
// against yet, the same "first scan is quiet" convention Wazuh's syscheck
// uses). A path whose hash changed since its baseline produces a
// file_modified Event; a path that existed before and no longer does
// produces file_deleted. The returned error, when non-nil, is always a
// state-file save failure -- Poll's own detection work has already
// completed and its Events are valid either way.
func (w *FIMWatcher) Poll() ([]detect.Event, error) {
	w.keepLoaded()
	w.loaded = nil
	var events []detect.Event
	emit := func(path string, e detect.Event) {
		if w.graced[path] || w.underDir(path) {
			if w.pending == nil {
				w.pending = map[string]pendingChange{}
			}
			if _, already := w.pending[path]; !already {
				w.pending[path] = pendingChange{seen: w.clock(), event: e}
			}
			return
		}
		events = append(events, e)
	}
	// the folders: files that appeared since the folder's first look, and files that went away
	inDirs := w.dirFiles()
	for _, d := range w.dirs {
		if _, known := w.baselines[dirMarker+d]; !known {
			// first look at this folder: everything in it is the baseline, quietly
			for f := range inDirs {
				if strings.HasPrefix(f, d+string(filepath.Separator)) {
					if info, err := os.Stat(f); err == nil {
						if h, err := hashFile(f); err == nil {
							w.baselines[f] = FileBaseline{ModTime: info.ModTime(), Size: info.Size(), Hash: h}
						}
					}
				}
			}
			w.baselines[dirMarker+d] = FileBaseline{Hash: "dir"}
		}
	}
	for path := range inDirs {
		if _, known := w.baselines[path]; known {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		hash, err := hashFile(path)
		if err != nil {
			continue
		}
		w.baselines[path] = FileBaseline{ModTime: info.ModTime(), Size: info.Size(), Hash: hash}
		emit(path, detect.Event{Source: "host-fim", Time: info.ModTime(), Kind: "file_created", Text: path,
			Fields: map[string]string{"path": path, "new_hash": hash}})
	}
	for path, prior := range w.baselines {
		if w.underDir(path) && !inDirs[path] {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				emit(path, detect.Event{Source: "host-fim", Time: w.clock(), Kind: "file_deleted", Text: path,
					Fields: map[string]string{"path": path, "prior_hash": prior.Hash}})
				delete(w.baselines, path)
			}
		}
	}
	var paths []string
	paths = append(paths, w.paths...)
	for p := range inDirs {
		paths = append(paths, p)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				if prior, known := w.baselines[path]; known {
					emit(path, detect.Event{
						Source: "host-fim",
						Time:   w.clock(),
						Kind:   "file_deleted",
						Text:   path,
						Fields: map[string]string{"path": path, "prior_hash": prior.Hash},
					})
					delete(w.baselines, path)
				}
			}
			continue // unreadable for another reason (permissions, transient); retry next poll
		}

		prior, known := w.baselines[path]
		if known && info.ModTime().Equal(prior.ModTime) && info.Size() == prior.Size {
			continue // cheap precheck says unchanged -- skip the hash entirely
		}

		hash, err := hashFile(path)
		if err != nil {
			continue // transient read error (e.g. concurrent write); retry next poll
		}
		next := FileBaseline{ModTime: info.ModTime(), Size: info.Size(), Hash: hash}

		if !known {
			w.baselines[path] = next
			continue
		}
		if hash != prior.Hash {
			emit(path, detect.Event{
				Source: "host-fim",
				Time:   info.ModTime(),
				Kind:   "file_modified",
				Text:   path,
				Fields: map[string]string{"path": path, "prior_hash": prior.Hash, "new_hash": hash},
			})
		}
		// Update the baseline even when content is unchanged (e.g. `touch`
		// moved mtime but not size/content) so the cheap precheck above
		// stays accurate against the file's current mtime.
		w.baselines[path] = next
	}
	// changes held for their grace period: reported now, with the content as it is now (it may have been signed meanwhile)
	for path, p := range w.pending {
		if w.clock().Sub(p.seen) < w.grace {
			continue
		}
		e := p.event
		if e.Kind != "file_deleted" {
			if h, err := hashFile(path); err == nil {
				e.Fields["new_hash"] = h
			} else if os.IsNotExist(err) {
				e.Kind = "file_deleted"
				delete(e.Fields, "new_hash")
			}
		}
		events = append(events, e)
		delete(w.pending, path)
	}
	return events, w.save()
}

// save is a no-op when no statePath was configured (NewFIMWatcher, used by
// tests). It writes to a temp file and renames over the target so a crash
// mid-write can never leave a truncated, unparseable state file behind --
// worst case after a crash is the previous, still-valid snapshot.
func (w *FIMWatcher) save() error {
	if w.statePath == "" {
		return nil
	}
	raw, err := json.MarshalIndent(w.baselines, "", "  ")
	if err != nil {
		return err
	}
	tmp := w.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.statePath)
}

// Run polls on an interval until ctx is done, reporting any state-save
// failure to onErr (detection itself continues regardless -- see Poll).
func (w *FIMWatcher) Run(ctx context.Context, interval time.Duration, onErr func(error), emit func(detect.Event)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := w.Poll()
			if err != nil && onErr != nil {
				onErr(err)
			}
			for _, e := range events {
				emit(e)
			}
		}
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
