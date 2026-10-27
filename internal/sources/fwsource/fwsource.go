// Package fwsource watches who knocks from outside: packets the firewall (ufw) blocked, and failed SSH logins. It reads the
// system journal (never the network), names where each address belongs from the offline IP database (internal/ipintel),
// and hands one event per knock to the detectors, which decide when a run of them is worth an alert.
//
// What it cannot know, it says: a blocked packet never completed a connection, so its source address may be forged; a
// failed login did complete one (TCP's handshake needs the reply to reach the sender), so that address is real.
//
// Reading the journal needs the systemd-journal group (packaging/heimdall-firewall.conf.example). Without it the source
// reports itself unavailable once and stops.
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
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
)

// Watcher polls the journal from where it left off (a cursor file in Heimdall's state folder).
type Watcher struct {
	CursorPath string
	Origins    *ipintel.Resolver
	Threats    *ipintel.Lists
	journalctl string
	// run is how journalctl is started (a test replaces it).
	run func(ctx context.Context, args ...string) ([]byte, error)
}

func NewWatcher(cursorPath string, origins *ipintel.Resolver) *Watcher {
	w := &Watcher{CursorPath: cursorPath, Origins: origins, journalctl: "journalctl"}
	w.run = func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, w.journalctl, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		var errb strings.Builder
		cmd.Stderr = &errb
		out, err := cmd.Output()
		if err != nil && len(out) == 0 {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
		}
		return out, nil
	}
	return w
}

// ErrNoAccess means the journal could not be read (Heimdall is not in the systemd-journal group).
var ErrNoAccess = errors.New("cannot read the system journal (add the systemd-journal group, see heimdall-firewall.conf.example)")

const maxPerPoll = 5000 // a flood is counted from what is read; the rest waits for the next poll

func (w *Watcher) args() []string {
	a := []string{"-o", "json", "--no-pager", "-q", "-n", fmt.Sprint(maxPerPoll),
		// SYSLOG_IDENTIFIER is whatever the writer says (logger -t sshd works for anyone), so the SSH lines must also come from
		// root: _UID is set by journald itself and cannot be forged
		"_TRANSPORT=kernel", "+", "SYSLOG_IDENTIFIER=sshd", "_UID=0", "+", "SYSLOG_IDENTIFIER=sshd-session", "_UID=0"}
	if c := w.cursor(); c != "" {
		return append(a, "--after-cursor="+c)
	}
	return append(a, "--since=-10min") // first run: not the whole history, only what is recent
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

// Poll reads the new journal entries and returns one event per knock.
func (w *Watcher) Poll(ctx context.Context) ([]detect.Event, error) {
	out, err := w.run(ctx, w.args()...)
	if err != nil {
		if strings.Contains(err.Error(), "No journal files were opened") || strings.Contains(err.Error(), "ermission") {
			return nil, ErrNoAccess
		}
		return nil, err
	}
	var events []detect.Event
	last := ""
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e struct {
			Message string `json:"MESSAGE"`
			Ident   string `json:"SYSLOG_IDENTIFIER"`
			TS      string `json:"__REALTIME_TIMESTAMP"`
			Cursor  string `json:"__CURSOR"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			// MESSAGE given as a byte array (not text): not a line this source reads, but reading moves past it
			var c struct {
				Cursor string `json:"__CURSOR"`
			}
			if json.Unmarshal(sc.Bytes(), &c) == nil && c.Cursor != "" {
				last = c.Cursor
			}
			continue
		}
		if e.Cursor != "" {
			last = e.Cursor
		}
		t := time.Now()
		var us int64
		if _, err := fmt.Sscan(e.TS, &us); err == nil && us > 0 {
			t = time.UnixMicro(us)
		}
		if ev, ok := w.parse(e.Message, e.Ident, t); ok {
			events = append(events, ev)
		}
	}
	if last != "" {
		if err := w.saveCursor(last); err != nil {
			return events, err
		}
	}
	return events, nil
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
		f := map[string]string{"src": ip.String(), "dst_port": kv["DPT"], "proto": kv["PROTO"], "iface": kv["IN"], "spoofable": "1"}
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

// Run polls until ctx ends. onUnavailable is called once (and the source stops) when the journal cannot be read.
func (w *Watcher) Run(ctx context.Context, interval time.Duration, onUnavailable func(error), onErr func(error), emit func(detect.Event)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		events, err := w.Poll(ctx)
		if errors.Is(err, ErrNoAccess) {
			onUnavailable(err)
			return
		}
		if err != nil {
			onErr(err)
		}
		for _, e := range events {
			emit(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
