package hostsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
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
	watched := make(map[string]bool, len(paths))
	for _, p := range paths {
		watched[p] = true
	}
	for path, b := range loaded {
		if watched[path] { // drop entries for paths no longer configured
			w.baselines[path] = b
		}
	}
	return w
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
	var events []detect.Event
	for _, path := range w.paths {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				if prior, known := w.baselines[path]; known {
					events = append(events, detect.Event{
						Source: "host-fim",
						Time:   time.Now(),
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
			events = append(events, detect.Event{
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
