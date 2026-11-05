// Package grants is the one gate for an AI agent asking for more than it has (Phase 4, docs/GRANTS.md): handing a task to a
// stronger model off this computer (escalation to Claude Code or a cloud tier) and a higher access tier (write, tests,
// shell). The agent may only ask. The owner decides, as root, at a terminal. The agent reads the answer from a file only root
// can write.
//
// Two files, two writers:
//   - requests (/var/lib/heimdall/grant-requests.json): written by heimdalld when an agent files a request over the API
//     (POST /v1/requests). The account behind each request comes from the kernel (internal/api/access.go), not from the request.
//   - decisions (/etc/heimdall/grants.json): written only by `heimdalld grant ...` running as root. The agent (Sarina's
//     go/heimdall/grants.go) reads this file directly, never an HTTP answer, so a program that takes port 8930 while Heimdall
//     is down cannot answer "approved". The file existing is what switches the gate on.
//
// An approval is refused unless it comes from a person: root, a terminal on standard input, and no Sarina process (by
// program or by account) among the approving command's ancestors (Guard). That is the "never self-approved" property: an
// agent with a shell cannot sudo without the owner's password, and if it ever could, the ancestor check still names it.
package grants

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	KindEscalation = "escalation"  // hand the conversation to another model tier (Detail: the tier's name, e.g. claude-cli)
	KindAccessTier = "access_tier" // a higher access tier (Detail: the tier number, "1".."3")

	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"

	DefaultRequests  = "/var/lib/heimdall/grant-requests.json"
	DefaultDecisions = "/etc/heimdall/grants.json"

	maxPending = 50 // more open requests than a person can read is itself a finding; the oldest are dropped
	// MaxEscalationFor bounds one approval: a hand-off is a decision about a task, not a standing permission.
	MaxEscalationFor = 24 * time.Hour
)

// Request is one ask, as filed.
type Request struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Detail    string    `json:"detail"`
	Reason    string    `json:"reason,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	UID       uint32    `json:"uid"`
	Time      time.Time `json:"time"`
	Count     int       `json:"count"` // the same ask repeated is merged, not queued again
}

// Escalation is an approved hand-off: to Tier, for SessionID (empty: any session), until Until.
type Escalation struct {
	RequestID string    `json:"request_id,omitempty"`
	Tier      string    `json:"tier"`
	SessionID string    `json:"session_id,omitempty"`
	Until     time.Time `json:"until"`
	By        string    `json:"by"`
}

// Decision records what the owner said about a request (approved or denied), for the record and for the asker.
type Decision struct {
	RequestID string    `json:"request_id"`
	Kind      string    `json:"kind"`
	Detail    string    `json:"detail"`
	Status    string    `json:"status"`
	By        string    `json:"by"`
	Time      time.Time `json:"time"`
}

// Decisions is /etc/heimdall/grants.json. AccessTier caps the agent's access tier (the agent uses the lower of this and its
// own setting); nil means the owner has not set one, which is read as 0 (read-only) by an agent that honours the gate.
type Decisions struct {
	AccessTier  *int         `json:"access_tier"`
	Escalations []Escalation `json:"escalations"`
	History     []Decision   `json:"history"`
}

// Store holds the two paths.
type Store struct {
	Requests  string
	Decisions string
}

func Default() Store { return Store{Requests: DefaultRequests, Decisions: DefaultDecisions} }

// readJSON never follows a link: root reads the requests file from a folder heimdalld can write.
func readJSON(path string, v any) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// mu orders the daemon's own writes; lock (flock on a side file) orders them with root's `heimdalld grant`.
var mu sync.Mutex

func (s Store) lock() (func(), error) {
	mu.Lock()
	f, err := os.OpenFile(s.Requests+".lock", os.O_RDONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		mu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		mu.Unlock()
		return nil, err
	}
	return func() { f.Close(); mu.Unlock() }, nil
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".grants-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	// root writing into heimdalld's folder leaves the file to the folder's owner, or the daemon could no longer update it
	if fi, err := os.Stat(filepath.Dir(path)); err == nil && os.Geteuid() == 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = tmp.Chown(int(st.Uid), int(st.Gid))
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Pending returns the open requests, oldest first.
func (s Store) Pending() ([]Request, error) {
	var rs []Request
	if err := readJSON(s.Requests, &rs); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return rs, nil
}

// Load reads the owner's decisions; ok is false when the file does not exist (the gate is off).
func (s Store) Load() (Decisions, bool, error) {
	var d Decisions
	err := readJSON(s.Decisions, &d)
	if errors.Is(err, os.ErrNotExist) {
		return d, false, nil
	}
	return d, err == nil, err
}

// Validate checks a request's shape before it is stored: only the two kinds, a short tier name or a tier number 1-3.
func Validate(r Request) error {
	switch r.Kind {
	case KindEscalation:
		if r.Detail == "" || len(r.Detail) > 64 || strings.ContainsAny(r.Detail, " \t\n/\\") {
			return errors.New("escalation needs detail: the tier's name (no spaces, at most 64 characters)")
		}
	case KindAccessTier:
		if r.Detail != "1" && r.Detail != "2" && r.Detail != "3" {
			return errors.New("access_tier needs detail 1, 2 or 3 (tier 4 is set up on the operating system by the owner)")
		}
	default:
		return fmt.Errorf("kind must be %q or %q", KindEscalation, KindAccessTier)
	}
	if len(r.Reason) > 1000 || len(r.SessionID) > 128 {
		return errors.New("reason (1000) or session_id (128) too long")
	}
	return nil
}

// File stores a request (heimdalld, from the API) and returns it with its id. The same kind, detail, session and account
// asked again is merged into the open request (Count goes up) instead of filling the list.
func (s Store) File(r Request, now time.Time) (Request, error) {
	if err := Validate(r); err != nil {
		return r, err
	}
	unlock, err := s.lock()
	if err != nil {
		return r, err
	}
	defer unlock()
	rs, err := s.Pending()
	if err != nil {
		return r, err
	}
	for i := range rs {
		o := &rs[i]
		if o.Kind == r.Kind && o.Detail == r.Detail && o.SessionID == r.SessionID && o.UID == r.UID {
			o.Count++
			if r.Reason != "" {
				o.Reason = r.Reason
			}
			return *o, writeJSON(s.Requests, rs, 0o640)
		}
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	r.ID, r.Time, r.Count = hex.EncodeToString(b), now.UTC(), 1
	rs = append(rs, r)
	if len(rs) > maxPending {
		rs = rs[len(rs)-maxPending:]
	}
	return r, writeJSON(s.Requests, rs, 0o640)
}

// Decide approves or denies a pending request (root, after Guard). An approved escalation lasts `for` (at most
// MaxEscalationFor); an approved access tier becomes the cap. The request leaves the pending list either way.
func (s Store) Decide(id string, approve bool, by string, dur time.Duration, now time.Time) (Decision, error) {
	unlock, err := s.lock()
	if err != nil {
		return Decision{}, err
	}
	defer unlock()
	rs, err := s.Pending()
	if err != nil {
		return Decision{}, err
	}
	idx := -1
	for i, r := range rs {
		if r.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return Decision{}, fmt.Errorf("no open request %q (heimdalld grant list)", id)
	}
	r := rs[idx]
	d, _, err := s.Load()
	if err != nil {
		return Decision{}, fmt.Errorf("%s is damaged, not changing it: %w", s.Decisions, err)
	}
	dec := Decision{RequestID: r.ID, Kind: r.Kind, Detail: r.Detail, Status: StatusDenied, By: by, Time: now.UTC()}
	if approve {
		dec.Status = StatusApproved
		switch r.Kind {
		case KindEscalation:
			if dur <= 0 || dur > MaxEscalationFor {
				return Decision{}, fmt.Errorf("an escalation is approved for at most %s", MaxEscalationFor)
			}
			d.Escalations = append(d.Escalations, Escalation{RequestID: r.ID, Tier: r.Detail, SessionID: r.SessionID, Until: now.Add(dur).UTC(), By: by})
		case KindAccessTier:
			n := int(r.Detail[0] - '0')
			d.AccessTier = &n
		}
	}
	d.prune(now)
	d.History = append(d.History, dec)
	if len(d.History) > 200 {
		d.History = d.History[len(d.History)-200:]
	}
	if err := writeJSON(s.Decisions, d, 0o644); err != nil {
		return Decision{}, err
	}
	rs = append(rs[:idx], rs[idx+1:]...)
	return dec, writeJSON(s.Requests, rs, 0o640)
}

// SetTier is the owner setting the access tier cap directly (no request needed), 0-3.
func (s Store) SetTier(n int, by string, now time.Time) error {
	if n < 0 || n > 3 {
		return errors.New("the access tier is 0, 1, 2 or 3")
	}
	d, _, err := s.Load()
	if err != nil {
		return fmt.Errorf("%s is damaged, not changing it: %w", s.Decisions, err)
	}
	d.AccessTier = &n
	d.prune(now)
	d.History = append(d.History, Decision{Kind: KindAccessTier, Detail: fmt.Sprint(n), Status: "set", By: by, Time: now.UTC()})
	return writeJSON(s.Decisions, d, 0o644)
}

// Revoke ends every approved escalation now.
func (s Store) Revoke(by string, now time.Time) error {
	d, _, err := s.Load()
	if err != nil {
		return err
	}
	d.Escalations = nil
	d.History = append(d.History, Decision{Kind: KindEscalation, Status: "revoked", By: by, Time: now.UTC()})
	return writeJSON(s.Decisions, d, 0o644)
}

func (d *Decisions) prune(now time.Time) {
	kept := d.Escalations[:0]
	for _, e := range d.Escalations {
		if e.Until.After(now) {
			kept = append(kept, e)
		}
	}
	d.Escalations = kept
}

// EscalationAllowed answers the agent's question (the same rule Sarina's reader applies): is a hand-off to tier, in session,
// approved right now?
func (d Decisions) EscalationAllowed(tier, session string, now time.Time) bool {
	for _, e := range d.Escalations {
		if e.Tier == tier && (e.SessionID == "" || e.SessionID == session) && now.Before(e.Until) {
			return true
		}
	}
	return false
}

// Sorted returns the pending requests newest first, for display.
func Sorted(rs []Request) []Request {
	out := append([]Request(nil), rs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}
