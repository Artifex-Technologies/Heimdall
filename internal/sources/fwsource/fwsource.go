// Package fwsource watches who knocks from outside: packets the firewall (ufw) blocked, and failed SSH logins. It reads the
// system journal (never the network), names where each address belongs from the offline IP database (internal/ipintel),
// and hands one event per knock to the detectors, which decide when a run of them is worth an alert.
//
// What it cannot know, it says: a blocked packet never completed a connection, so its source address may be forged; a
// failed login did complete one (TCP's handshake needs the reply to reach the sender), so that address is real.
//
// Reading the journal needs the systemd-journal group (packaging/heimdall-firewall.conf.example). Without it the source
// reports itself unavailable once and stops.
//
// One journalctl --follow runs for as long as heimdalld does (started again from the last entry read if it ends), instead of
// a new journalctl every 15 seconds: each start opened and searched every journal file again (2026-11-09).
package fwsource

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
)

// Watcher follows the journal from where it left off (a cursor file in Heimdall's state folder).
type Watcher struct {
	CursorPath string
	Origins    *ipintel.Resolver
	Threats    *ipintel.Lists
	journalctl string // the program (a test puts a fake one here)
}

func NewWatcher(cursorPath string, origins *ipintel.Resolver) *Watcher {
	return &Watcher{CursorPath: cursorPath, Origins: origins, journalctl: "journalctl"}
}

// ErrNoAccess means the journal could not be read (Heimdall is not in the systemd-journal group).
var ErrNoAccess = errors.New("cannot read the system journal (add the systemd-journal group, see heimdall-firewall.conf.example)")

// saveAfter is how long after an entry its cursor is written: a burst of knocks is one write, and a crash replays at most
// this much (the entries were already passed on; none is ever skipped).
const saveAfter = time.Second

// args follows the journal after cursor ("" on a first run: only the last 10 minutes, not the whole history).
func (w *Watcher) args(cursor string) []string {
	a := []string{"-o", "json", "--no-pager", "-q", "--follow",
		// SYSLOG_IDENTIFIER is whatever the writer says (logger -t sshd works for anyone), so the SSH lines must also come from
		// root: _UID is set by journald itself and cannot be forged
		"_TRANSPORT=kernel", "+", "SYSLOG_IDENTIFIER=sshd", "_UID=0", "+", "SYSLOG_IDENTIFIER=sshd-session", "_UID=0"}
	if cursor != "" {
		return append(a, "--after-cursor="+cursor)
	}
	return append(a, "--since=-10min")
}

// cursor is where the last poll stopped (journalctl's own --cursor-file cannot be combined with --since, so it is kept here).
func (w *Watcher) cursor() string {
	b, err := os.ReadFile(w.CursorPath)
	if err != nil {
		return ""
	}
	c := strings.TrimSpace(string(b))
	if len(c) > 512 || strings.ContainsAny(c, "\n\x00") {
		return ""
	}
	return c
}

func (w *Watcher) saveCursor(c string) error {
	tmp := w.CursorPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(c+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.CursorPath)
}

// entry reads one journal line: the knock in it, if any, and its cursor ("" when it has none).
func (w *Watcher) entry(line []byte) (ev detect.Event, cursor string, ok bool) {
	var e struct {
		Message string `json:"MESSAGE"`
		Ident   string `json:"SYSLOG_IDENTIFIER"`
		TS      string `json:"__REALTIME_TIMESTAMP"`
		Cursor  string `json:"__CURSOR"`
	}
	if json.Unmarshal(line, &e) != nil {
		// MESSAGE given as a byte array (not text): not a line this source reads, but reading moves past it
		var c struct {
			Cursor string `json:"__CURSOR"`
		}
		if json.Unmarshal(line, &c) == nil {
			return detect.Event{}, c.Cursor, false
		}
		return detect.Event{}, "", false
	}
	t := time.Now()
	var us int64
	if _, err := fmt.Sscan(e.TS, &us); err == nil && us > 0 {
		t = time.UnixMicro(us)
	}
	ev, ok = w.parse(e.Message, e.Ident, t)
	return ev, e.Cursor, ok
}

var (
	ufwRx   = regexp.MustCompile(`\[UFW (BLOCK|LIMIT BLOCK)\]`)
	kvRx    = regexp.MustCompile(`\b(IN|SRC|DST|PROTO|SPT|DPT)=(\S*)`)
	sshFail = []*regexp.Regexp{
		regexp.MustCompile(`^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port \d+`),
		regexp.MustCompile(`^Invalid user (\S*) from (\S+) port \d+`),
		regexp.MustCompile(`^Connection (?:closed|reset) by (?:authenticating|invalid) user (\S+) (\S+) port \d+ \[preauth\]`),
		regexp.MustCompile(`^error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port \d+`),
	}
)

func (w *Watcher) parse(msg, ident string, t time.Time) (detect.Event, bool) {
	if ufwRx.MatchString(msg) {
		kv := map[string]string{}
		for _, m := range kvRx.FindAllStringSubmatch(msg, -1) {
			kv[m[1]] = m[2]
		}
		ip := net.ParseIP(kv["SRC"])
		if ip == nil || kv["IN"] == "" { // IN empty: an outgoing packet this computer sent, not a knock
			return detect.Event{}, false
		}
		f := map[string]string{"src": ip.String(), "src_port": kv["SPT"], "dst_port": kv["DPT"], "proto": kv["PROTO"], "iface": kv["IN"], "spoofable": "1"}
		o := w.origin(ip, f)
		port := kv["DPT"]
		if port == "" {
			port = "-"
		}
		return detect.Event{Source: "host-firewall", Time: t, Kind: "firewall_block", Fields: f,
			Text: fmt.Sprintf("firewall blocked %s %s from %s (%s) to port %s", kv["PROTO"], kv["IN"], ip, o, port)}, true
	}
	if !strings.HasPrefix(ident, "sshd") {
		return detect.Event{}, false
	}
	for _, rx := range sshFail {
		m := rx.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		ip := net.ParseIP(m[2])
		if ip == nil {
			return detect.Event{}, false
		}
		f := map[string]string{"src": ip.String(), "service": "ssh", "user": sanitize(m[1])}
		o := w.origin(ip, f)
		return detect.Event{Source: "host-login", Time: t, Kind: "login_failure", Fields: f,
			Text: fmt.Sprintf("failed SSH login as %q from %s (%s)", f["user"], ip, o)}, true
	}
	return detect.Event{}, false
}

func (w *Watcher) origin(ip net.IP, f map[string]string) ipintel.Origin {
	if w.Origins == nil {
		return ipintel.Origin{Scope: "public"}
	}
	o := w.Origins.Lookup(ip)
	for k, v := range o.Fields("origin_") {
		f[k] = v
	}
	f["origin"] = o.String()
	if l := w.Threats.Match(ip); len(l) > 0 {
		f["origin_listed"] = strings.Join(l, ",")
		f["origin"] += "; on threat lists: " + f["origin_listed"]
	}
	return o
}

// sanitize keeps a user name printable and short: it came from whoever was knocking.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return '?'
		}
		return r
	}, s)
	if len(s) > 32 {
		s = s[:32] + "..."
	}
	return s
}

// Run follows the journal until ctx ends, with one journalctl --follow; if it ends, it is started again after restart,
// from the last entry read. The cursor of the last entry read is written to CursorPath shortly after it (saveAfter) and
// when Run returns, so a restart of heimdalld goes on after it. onUnavailable is called once (and the source stops) when
// the journal cannot be read.
func (w *Watcher) Run(ctx context.Context, restart time.Duration, onUnavailable func(error), onErr func(error), emit func(detect.Event)) {
	c := &cursorState{w: w, onErr: onErr}
	c.at = w.cursor()
	c.saved = c.at
	defer c.save()
	lastErr := ""
	for ctx.Err() == nil {
		read, stderr, err := w.follow(ctx, c, emit)
		c.save()
		if ctx.Err() != nil {
			return
		}
		if read == 0 && (strings.Contains(stderr, "No journal files were opened") || strings.Contains(stderr, "ermission")) {
			onUnavailable(ErrNoAccess)
			return
		}
		if msg := fmt.Sprintf("journalctl ended (%v: %s); following again in %s", err, strings.TrimSpace(stderr), restart); msg != lastErr {
			onErr(errors.New(msg)) // the same trouble again and again is said once
			lastErr = msg
		}
		select {
		case <-ctx.Done():
		case <-time.After(restart):
		}
	}
}

// cursorState is the last entry read and the last one written to the cursor file.
type cursorState struct {
	w         *Watcher
	onErr     func(error)
	at, saved string
}

func (c *cursorState) save() {
	if c.at == c.saved {
		return
	}
	if err := c.w.saveCursor(c.at); err != nil {
		c.onErr(err)
		return
	}
	c.saved = c.at
}

// follow runs one journalctl --follow from c.at, passing each knock to emit, until it ends or ctx does. It returns how many
// lines were read and what journalctl said on stderr (the start of it).
func (w *Watcher) follow(ctx context.Context, c *cursorState, emit func(detect.Event)) (int, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.journalctl, w.args(c.at)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	errb := &headBuffer{max: 4 << 10}
	cmd.Stderr = errb
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, "", err
	}
	if err := cmd.Start(); err != nil {
		return 0, "", err
	}
	lines := make(chan []byte, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			select {
			case lines <- append([]byte(nil), sc.Bytes()...):
			case <-ctx.Done():
				return
			}
		}
	}()
	flush := time.NewTimer(time.Hour)
	flush.Stop()
	defer flush.Stop()
	armed, read := false, 0
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				err := cmd.Wait()
				return read, errb.String(), err
			}
			read++
			ev, cursor, isKnock := w.entry(line)
			if isKnock {
				emit(ev)
			}
			if cursor != "" {
				c.at = cursor
				if !armed {
					flush.Reset(saveAfter)
					armed = true
				}
			}
		case <-flush.C:
			armed = false
			c.save()
		case <-ctx.Done():
			cancel()
			for range lines { // the reader ends once journalctl is gone
			}
			return read, errb.String(), cmd.Wait()
		}
	}
}

// headBuffer keeps the first max bytes written to it (journalctl's complaints are short; a flood of them is not kept).
type headBuffer struct {
	mu  sync.Mutex
	b   []byte
	max int
}

func (h *headBuffer) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if room := h.max - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (h *headBuffer) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return string(h.b)
}
