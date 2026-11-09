package agentsource

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// rescanEvery is how often the whole folder is looked at while it is watched, so a change whose event never came (the
// kernel's queue overflowed, or a watch could not be added in time) is still read within this long.
const rescanEvery = 10 * time.Minute

// dirMask is what the kernel reports about the session folder and its agent/ folder: a file written and closed, a file
// renamed into place (how Sarina saves), a new file or folder, changed permissions (an unreadable file may have become
// readable), and the folder itself going away.
const dirMask = syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_CREATE | syscall.IN_ATTRIB |
	syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF | syscall.IN_ONLYDIR

type inotifyEvent struct {
	wd   int32
	mask uint32
	name string
}

// watch is the kernel's watch on the session folder and on its agent/ folder.
type watch struct {
	f          *os.File
	fd         int
	dir, agent int32 // watch descriptors; agent is -1 while there is no agent/ folder
	events     chan []inotifyEvent
	done       chan struct{}
}

func newWatch(dir string) (*watch, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	// non-blocking: reads go through Go's poller, and closing the file ends a read in progress
	ws := &watch{f: os.NewFile(uintptr(fd), "inotify"), fd: fd, agent: -1, events: make(chan []inotifyEvent, 4), done: make(chan struct{})}
	wd, err := syscall.InotifyAddWatch(fd, dir, dirMask)
	if err != nil {
		ws.f.Close()
		return nil, err
	}
	ws.dir = int32(wd)
	ws.addAgent(dir)
	go ws.read()
	return ws, nil
}

// addAgent watches dir/agent, where the agent's own session files are; false when there is no such folder.
func (ws *watch) addAgent(dir string) bool {
	wd, err := syscall.InotifyAddWatch(ws.fd, filepath.Join(dir, "agent"), dirMask)
	if err != nil {
		return false
	}
	ws.agent = int32(wd)
	return true
}

func (ws *watch) dropAgent() {
	_, _ = syscall.InotifyRmWatch(ws.fd, uint32(ws.agent)) // a moved folder keeps its watch; a deleted one has none left
	ws.agent = -1
}

func (ws *watch) close() {
	close(ws.done)
	ws.f.Close()
}

// read passes the kernel's events on in batches until the watch is closed.
func (ws *watch) read() {
	defer close(ws.events)
	buf := make([]byte, 64<<10)
	for {
		n, err := ws.f.Read(buf)
		if err != nil {
			return
		}
		var evs []inotifyEvent
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			// struct inotify_event: wd, mask, cookie, len, then len bytes of NUL-padded name
			wd := int32(binary.NativeEndian.Uint32(buf[off:]))
			mask := binary.NativeEndian.Uint32(buf[off+4:])
			end := off + syscall.SizeofInotifyEvent + int(binary.NativeEndian.Uint32(buf[off+12:]))
			if end > n {
				break
			}
			name := strings.TrimRight(string(buf[off+syscall.SizeofInotifyEvent:end]), "\x00")
			evs = append(evs, inotifyEvent{wd, mask, name})
			off = end
		}
		select {
		case ws.events <- evs:
		case <-ws.done:
			return
		}
	}
}

// Run reads the sessions until ctx is done, delivering every Event to emit in order. It looks at every file once, then
// waits for the kernel to say a session was saved and reads only that file: nothing runs while Sarina is idle. Changed files
// are read at once, and again at most once per interval while they keep changing (a long agent turn saves often). A file
// that is not valid JSON yet is looked at again one interval later (the settle window), and the whole folder every
// rescanEvery. While the folder cannot be watched (missing, unreadable, or no inotify) it is looked at every interval, as
// before. Errors (e.g. the folder not existing yet) are not fatal: the folder may only appear with Sarina's first run.
func (w *Watcher) Run(ctx context.Context, interval time.Duration, onErr func(error), emit func(detect.Event)) {
	lastErr, lastWatchErr := "", ""
	deliver := func(events []detect.Event, err error) {
		// A persistent directory problem is reported once, not every look.
		if err != nil && err.Error() != lastErr && onErr != nil {
			onErr(err)
		}
		lastErr = ""
		if err != nil {
			lastErr = err.Error()
		}
		for _, i := range w.Issues() {
			if onErr != nil {
				onErr(i)
			}
		}
		for _, e := range events {
			emit(e)
		}
	}
	for ctx.Err() == nil {
		ws, werr := newWatch(w.dir) // before the look, so nothing saved in between is missed
		deliver(w.Poll())
		if werr == nil {
			lastWatchErr = ""
			w.follow(ctx, ws, interval, deliver)
			ws.close()
			continue
		}
		// a missing folder was reported by Poll; any other reason it cannot be watched is said once
		if _, err := os.Stat(w.dir); err == nil && werr.Error() != lastWatchErr && onErr != nil {
			onErr(fmt.Errorf("agentsource: cannot watch %s (%v); looking at it every %s instead", w.dir, werr, interval))
		}
		lastWatchErr = werr.Error()
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}

// follow handles the kernel's events until ctx is done or the folder's watch is gone (deleted or moved: Run watches the
// path again).
func (w *Watcher) follow(ctx context.Context, ws *watch, interval time.Duration, deliver func([]detect.Event, error)) {
	rescan := time.NewTicker(rescanEvery)
	defer rescan.Stop()
	due := time.NewTimer(time.Hour)
	due.Stop()
	defer due.Stop()
	armed := false
	changed := map[string]bool{}
	var last time.Time // when changed files were last read
	again := func() {
		for p := range w.unsettled { // not valid JSON yet: look again one interval later
			changed[p] = true
		}
	}
	full := func() {
		deliver(w.Poll())
		again()
	}
	full() // what the look before the watch found unsettled
	for {
		if len(changed) > 0 && !armed {
			due.Reset(max(0, interval-time.Since(last)))
			armed = true
		}
		select {
		case <-ctx.Done():
			return
		case <-rescan.C:
			full()
		case <-due.C:
			armed = false
			paths := make([]string, 0, len(changed))
			for p := range changed {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			clear(changed)
			last = time.Now()
			deliver(w.checkFiles(paths), nil)
			again()
		case evs, ok := <-ws.events:
			if !ok {
				return
			}
			for _, ev := range evs {
				switch {
				case ev.mask&syscall.IN_Q_OVERFLOW != 0: // events were dropped: look at everything
					full()
				case ev.wd == ws.dir && ev.mask&(syscall.IN_IGNORED|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0:
					return
				case ev.wd == ws.agent && ev.mask&(syscall.IN_IGNORED|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0:
					ws.dropAgent()
				case ev.wd == ws.dir && ev.name == "agent" && ev.mask&syscall.IN_ISDIR != 0 && ev.mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0:
					if ws.agent < 0 && ws.addAgent(w.dir) {
						full() // sessions may have come with the folder
					}
				case strings.HasSuffix(ev.name, ".json") && ev.wd == ws.dir:
					changed[filepath.Join(w.dir, ev.name)] = true
				case strings.HasSuffix(ev.name, ".json") && ev.wd == ws.agent:
					changed[filepath.Join(w.dir, "agent", ev.name)] = true
				}
			}
		}
	}
}
