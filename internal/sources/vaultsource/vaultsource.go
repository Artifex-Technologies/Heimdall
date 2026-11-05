// Package vaultsource watches the notes of an AI agent's vault (Sarina's Obsidian vault, docs/VAULT.md in Sarina) at rest.
// The session reader (agentsource) sees a planted instruction only once the agent has read it into a session; a poisoned
// note sits in the vault before that, and the vault's search can surface it any day. Here every note is checked when it
// appears or changes, so the alert comes whether or not the agent ever opens the note (Sarina's eval vault-note-injection:
// in the runs that failed she only searched, and the planted line never reached her session).
//
// No polling: the kernel's inotify tells when a note is closed after writing or moved in; nothing runs while the vault is
// still. A note's SHA-256 is kept in a state file, so a restart only checks what changed meanwhile and a poisoned note is
// reported once per content, not once per start.
package vaultsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

const (
	// maxNote bounds what is read of one note; a real note is a few KB.
	maxNote = 1 << 20
	// maxNotes bounds the walk of one vault, so a wrong path (a whole home folder) cannot keep Heimdall busy.
	maxNotes = 20000
)

// Watcher checks the notes under Roots.
type Watcher struct {
	Roots     []string
	StatePath string // path -> SHA-256 of the content last checked; empty: kept in memory only

	seen map[string]string
	// Issues reports a vault that cannot be read or watched (once per start), so a blind spot is not silent.
	Issues func(error)
}

// skipDir are folders of a vault that hold no notes the agent reads: version control, the editor's settings, deleted notes.
func skipDir(name string) bool {
	return name == ".git" || name == ".obsidian" || name == ".trash" || name == ".port_sessions"
}

func isNote(name string) bool { return strings.HasSuffix(strings.ToLower(name), ".md") }

func (w *Watcher) load() {
	w.seen = map[string]string{}
	if w.StatePath == "" {
		return
	}
	if b, err := os.ReadFile(w.StatePath); err == nil {
		_ = json.Unmarshal(b, &w.seen)
	}
}

func (w *Watcher) save() {
	if w.StatePath == "" {
		return
	}
	b, err := json.Marshal(w.seen)
	if err != nil {
		return
	}
	tmp := w.StatePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, w.StatePath)
	}
}

// readNote reads one note without following a link, refusing anything but a regular file of at most maxNote bytes: the vault
// belongs to a person and an agent, and Heimdall may hold a capability that reads any file, so a link planted in the vault
// must not make it read (and quote in an alert) a file outside it.
func readNote(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxNote {
		return nil, errors.New("not a regular note of at most 1 MiB")
	}
	return io.ReadAll(io.LimitReader(f, maxNote))
}

// check returns an event for the note when its content is new to the watcher.
func (w *Watcher) check(root, path string) (detect.Event, bool) {
	b, err := readNote(path)
	if err != nil {
		return detect.Event{}, false
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	if w.seen[path] == h {
		return detect.Event{}, false
	}
	w.seen[path] = h
	rel, _ := filepath.Rel(root, path)
	return detect.Event{Source: "agent-vault", Time: time.Now(), Kind: "vault_note", Text: string(b),
		Fields: map[string]string{"vault": root, "note": rel, "path": path, "role": "vault"}}, true
}

// Scan checks every note under the roots once and returns events for those whose content is new (all of them on a first
// run without state). The list of folders is returned for the watch.
func (w *Watcher) Scan() ([]detect.Event, []string) {
	if w.seen == nil {
		w.load()
	}
	var events []detect.Event
	var dirs []string
	for _, root := range w.Roots {
		n := 0
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subfolder: skip it, keep the rest
			}
			if d.IsDir() {
				if p != root && skipDir(d.Name()) {
					return fs.SkipDir
				}
				dirs = append(dirs, p)
				return nil
			}
			if !d.Type().IsRegular() || !isNote(d.Name()) {
				return nil // links are never followed
			}
			if n++; n > maxNotes {
				return fs.SkipAll
			}
			if e, ok := w.check(root, p); ok {
				events = append(events, e)
			}
			return nil
		})
		if err != nil && w.Issues != nil {
			w.Issues(err)
		}
		if _, err := os.Stat(root); err != nil && w.Issues != nil {
			w.Issues(err)
		}
	}
	w.save()
	return events, dirs
}

// rootOf is the configured vault a path is in.
func (w *Watcher) rootOf(path string) string {
	for _, r := range w.Roots {
		if path == r || strings.HasPrefix(path, r+string(os.PathSeparator)) {
			return r
		}
	}
	return ""
}

const watchMask = syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_CREATE | syscall.IN_DONT_FOLLOW

// Run scans once, then waits for the kernel to report a written or moved-in note and checks only that note. It returns when
// ctx ends. Without inotify (or with no vault) it returns after the scan.
func (w *Watcher) Run(ctx context.Context, emit func(detect.Event)) {
	events, dirs := w.Scan()
	for _, e := range events {
		emit(e)
	}
	if len(dirs) == 0 {
		return
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		if w.Issues != nil {
			w.Issues(err)
		}
		return
	}
	f := os.NewFile(uintptr(fd), "inotify") // non-blocking: reads go through Go's poller, Close wakes them
	defer f.Close()
	go func() { <-ctx.Done(); f.Close() }()

	paths := map[int32]string{}
	add := func(dir string) {
		wd, err := syscall.InotifyAddWatch(fd, dir, watchMask)
		if err == nil {
			paths[int32(wd)] = dir
		}
	}
	for _, d := range dirs {
		add(d)
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if err != nil {
			return
		}
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
			name := ""
			if ev.Len > 0 {
				raw := buf[off+syscall.SizeofInotifyEvent : off+syscall.SizeofInotifyEvent+int(ev.Len)]
				name = strings.TrimRight(string(raw), "\x00")
			}
			off += syscall.SizeofInotifyEvent + int(ev.Len)
			dir, ok := paths[ev.Wd]
			if !ok || name == "" {
				continue
			}
			p := filepath.Join(dir, name)
			root := w.rootOf(p)
			if root == "" {
				continue
			}
			if ev.Mask&syscall.IN_ISDIR != 0 {
				if ev.Mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 && !skipDir(name) {
					add(p) // a new folder: watch it, and check notes moved in with it
					sub := &Watcher{Roots: []string{p}, seen: w.seen}
					es, ds := sub.Scan()
					for _, d := range ds {
						if d != p {
							add(d)
						}
					}
					for _, e := range es {
						e.Fields["vault"], e.Fields["note"] = root, strings.TrimPrefix(e.Fields["path"], root+"/")
						emit(e)
					}
					w.save()
				}
				continue
			}
			if !isNote(name) || ev.Mask&(syscall.IN_CLOSE_WRITE|syscall.IN_MOVED_TO) == 0 {
				continue
			}
			if e, ok := w.check(root, p); ok {
				w.save()
				emit(e)
			}
		}
	}
}
