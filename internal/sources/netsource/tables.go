package netsource

import (
	"context"
	"os"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Tables reads the kernel's TCP socket tables (/proc/net/tcp and tcp6) once per interval and gives the same read to each
// watcher that needs them: the exposure check of the ecosystem's ports, the connection log and the new-listener check. Each
// used to read and parse both files on its own clock, so Heimdall woke three times for what one read answers. The interval
// is the shortest any of them asks for (10 s with the connection log, else 15 s); a watcher that asks for a longer one
// looks at every read that is at least that far (less half an interval) after its last.
type Tables struct {
	paths []string
	users []*tableUser
}

type tableUser struct {
	every         time.Duration
	last          time.Time
	observe       func([]socketEntry) ([]detect.Event, error)
	onUnavailable func(error)
	onErr         func(error)
}

func NewTables() *Tables {
	return &Tables{paths: []string{"/proc/net/tcp", "/proc/net/tcp6"}}
}

// readTables reads and parses the socket tables. A missing file is skipped (tcp6 is absent with IPv6 off); an error is
// returned only when none could be opened, and os.IsNotExist on it means this system has no /proc to read.
func readTables(paths []string) ([]socketEntry, error) {
	var entries []socketEntry
	var lastErr error
	opened := 0
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			lastErr = err
			continue
		}
		opened++
		parsed, _ := ParseProcNetTCP(f)
		f.Close()
		entries = append(entries, parsed...)
	}
	if opened == 0 {
		return nil, lastErr
	}
	return entries, nil
}

// Ports adds the exposure check of the ecosystem's ports. Its first look only learns what is already there, as before.
func (t *Tables) Ports(w *PortWatcher, every time.Duration, onUnavailable, onErr func(error)) {
	first := true
	t.users = append(t.users, &tableUser{every: every, onUnavailable: onUnavailable, onErr: onErr,
		observe: func(e []socketEntry) ([]detect.Event, error) {
			events := w.observe(e)
			if first {
				first = false
				return nil, nil
			}
			return events, nil
		}})
}

// Connections adds the connection log.
func (t *Tables) Connections(w *ConnWatcher, every time.Duration, onUnavailable, onErr func(error)) {
	t.users = append(t.users, &tableUser{every: every, observe: w.observe, onUnavailable: onUnavailable, onErr: onErr})
}

// Listeners adds the new-listener check.
func (t *Tables) Listeners(w *ListenWatcher, every time.Duration) {
	t.users = append(t.users, &tableUser{every: every,
		observe: func(e []socketEntry) ([]detect.Event, error) { return w.observe(e), nil }})
}

// Run reads the tables at once and then every interval until ctx is done, passing each read to the watchers due for one.
// Without /proc it tells each watcher once and stops; a later failed read goes to each watcher's onErr.
func (t *Tables) Run(ctx context.Context, emit func(detect.Event)) {
	if len(t.users) == 0 {
		return
	}
	tick := t.tick()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for first := true; t.step(time.Now(), tick, first, emit); first = false {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick is the shortest interval a watcher asks for.
func (t *Tables) tick() time.Duration {
	tick := t.users[0].every
	for _, u := range t.users[1:] {
		tick = min(tick, u.every)
	}
	return tick
}

// step makes one read and passes it to the watchers due at now; false when there is no /proc to read.
func (t *Tables) step(now time.Time, tick time.Duration, first bool, emit func(detect.Event)) bool {
	entries, err := readTables(t.paths)
	switch {
	case err != nil && first && os.IsNotExist(err):
		for _, u := range t.users {
			if u.onUnavailable != nil {
				u.onUnavailable(err)
			}
		}
		return false
	case err != nil:
		for _, u := range t.users {
			if u.onErr != nil {
				u.onErr(err)
			}
		}
		return true
	}
	for _, u := range t.users {
		if !u.last.IsZero() && now.Sub(u.last)+tick/2 < u.every {
			continue
		}
		u.last = now
		events, err := u.observe(entries)
		if err != nil && u.onErr != nil {
			u.onErr(err)
		}
		for _, e := range events {
			emit(e)
		}
	}
	return true
}
