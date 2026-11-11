package parity

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/grants"
)

// GrantOp is one owner decision through the Go store: the two files before, the operation, and the files after (or the
// error). Absent files are nil.
type GrantOp struct {
	Requests  *string `json:"requests"`
	Decisions *string `json:"decisions"`
	Op        string  `json:"op"` // approve ID | deny ID | tier N | revoke | status
	By        string  `json:"by"`
	Dur       int64   `json:"dur"`
	Now       string  `json:"now"`
	// golden
	Error        string  `json:"error"`
	Result       string  `json:"result"` // the decision ("approved: escalation x") or Load's view (on, tier, live hand-offs)
	RequestsOut  *string `json:"requests_out"`
	DecisionsOut *string `json:"decisions_out"`
}

// GuardCase is a made-up /proc: the processes from this one ("SELF") up, and what Guard says (the pid of this process
// written as SELF).
type GuardCase struct {
	Procs    []GuardProc `json:"procs"`
	Terminal bool        `json:"terminal"`
	Error    string      `json:"error"`
}

type GuardProc struct {
	PID     string  `json:"pid"`
	Status  *string `json:"status"` // "{ppid}" in it is the parent's pid
	Cmdline *string `json:"cmdline"`
	Exe     string  `json:"exe"` // a link's target, or none
}

func sp(s string) *string { return &s }

func readOpt(p string) *string {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return sp(string(b))
}

func grantOps(tmp func() string) ([]GrantOp, error) {
	now := time.Date(2026, 11, 10, 20, 0, 0, 5, time.FixedZone("", -5*3600))
	reqs := `[
  {"id": "aa11bb22", "kind": "escalation", "detail": "claude-cli", "reason": "the build \"fails\"", "session_id": "s-1", "uid": 961, "time": "2026-11-09T10:00:00.5Z", "count": 2},
  {"id": "cc33dd44", "kind": "access_tier", "detail": "2", "uid": 961, "time": "2026-11-10T08:30:00+01:00", "count": 1, "extra": true},
  {"ID": "ee55ff66", "Kind": "escalation", "detail": "cloud-tier", "uid": 1000, "time": "2026-11-01T00:00:00Z", "count": 1},
  {"id": "dup", "kind": "access_tier", "detail": "1", "uid": 5, "time": "2026-11-02T00:00:00Z", "count": 1},
  {"id": "dup", "kind": "access_tier", "detail": "3", "uid": 6, "time": "2026-11-03T00:00:00Z", "count": 1}
]`
	decs := []*string{nil, sp(`{}`), sp(`null`), sp(`{"access_tier": null, "escalations": [], "history": null}`),
		sp(`{"access_tier": 3, "escalations": [{"request_id": "x", "tier": "a", "until": "2026-11-11T00:00:00Z", "by": "o"}, {"tier": "b", "session_id": "s", "until": "2026-11-10T00:00:00-05:00", "by": "o"}], "history": [{"request_id": "x", "kind": "escalation", "detail": "a", "status": "approved", "by": "o", "time": "2026-11-01T00:00:00Z"}], "unknown": 1}`),
		sp(`{"access_tier": "2"}`), sp(`{"escalations": [1]}`), sp(`[`), sp(`{"ACCESS_TIER": 1, "Escalations": null}`)}
	ops := []struct {
		op  string
		dur time.Duration
	}{{"approve aa11bb22", time.Hour}, {"approve aa11bb22", 0}, {"approve aa11bb22", 25 * time.Hour}, {"approve aa11bb22", 24 * time.Hour},
		{"approve cc33dd44", time.Hour}, {"deny aa11bb22", time.Hour}, {"approve ee55ff66", time.Minute}, {"approve dup", time.Hour},
		{"deny nope", time.Hour}, {"tier 0", 0}, {"tier 3", 0}, {"tier 4", 0}, {"tier -1", 0}, {"revoke", 0}, {"status", 0}}
	var out []GrantOp
	for _, d := range decs {
		for _, o := range ops {
			for _, withReqs := range []bool{true, false} {
				if !withReqs && strings.HasPrefix(o.op, "tier") {
					continue
				}
				dir := tmp()
				st := grants.Store{Requests: filepath.Join(dir, "requests.json"), Decisions: filepath.Join(dir, "grants.json")}
				c := GrantOp{Decisions: d, Op: o.op, By: "owner", Dur: int64(o.dur), Now: now.Format(time.RFC3339Nano)}
				if withReqs {
					c.Requests = sp(reqs)
					if err := os.WriteFile(st.Requests, []byte(reqs), 0o640); err != nil {
						return nil, err
					}
				}
				if d != nil {
					if err := os.WriteFile(st.Decisions, []byte(*d), 0o644); err != nil {
						return nil, err
					}
				}
				f := strings.Fields(o.op)
				var err error
				switch f[0] {
				case "approve", "deny":
					var dec grants.Decision
					dec, err = st.Decide(f[1], f[0] == "approve", c.By, o.dur, now)
					if err == nil {
						c.Result = dec.Status + ": " + dec.Kind + " " + dec.Detail
					}
				case "tier":
					n, _ := strconv.Atoi(f[1])
					err = st.SetTier(n, c.By, now)
				case "revoke":
					err = st.Revoke(c.By, now)
				case "status":
					dd, on, lerr := st.Load()
					err = lerr
					tier := "nil"
					if dd.AccessTier != nil {
						tier = strconv.Itoa(*dd.AccessTier)
					}
					var live []string
					for _, e := range dd.Escalations {
						if dd.EscalationAllowed(e.Tier, e.SessionID, now) {
							live = append(live, e.Tier)
						}
					}
					c.Result = "on=" + strconv.FormatBool(on) + " tier=" + tier + " live=" + strings.Join(live, ",")
					if p, perr := st.Pending(); perr == nil {
						for _, r := range grants.Sorted(p) {
							c.Result += " " + r.ID
						}
					}
				}
				if err != nil {
					c.Error = strings.ReplaceAll(err.Error(), dir, "DIR")
				}
				c.RequestsOut, c.DecisionsOut = readOpt(st.Requests), readOpt(st.Decisions)
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func guardCases(tmp func() string) ([]GuardCase, error) {
	st := func(ppid string, uid string) *string {
		return sp("Name:\tx\nState:\tS\nPPid:\t" + ppid + "\nUid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\n")
	}
	chain := func(names ...string) []GuardProc {
		var ps []GuardProc
		for i, n := range names {
			pid := "SELF"
			if i > 0 {
				pid = strconv.Itoa(5000 + i)
			}
			parent := strconv.Itoa(5000 + i + 1)
			if i == len(names)-1 {
				parent = "1"
			}
			ps = append(ps, GuardProc{PID: pid, Status: st(parent, "0"), Cmdline: sp(n + "\x00--flag\x00")})
		}
		return ps
	}
	cases := []GuardCase{
		{Procs: chain("heimdalld", "sudo", "bash", "kitty"), Terminal: true},
		{Procs: chain("heimdalld", "sudo", "bash", "kitty"), Terminal: false},
		{Procs: chain("heimdalld", "sudo", "/usr/bin/sarina", "bash"), Terminal: true},
		{Procs: chain("heimdalld", "sarina-service"), Terminal: true},
		{Procs: chain("heimdalld", "sarina-helper"), Terminal: true},
		{Procs: chain("heimdalld", "python3"), Terminal: true},
		{Procs: []GuardProc{{PID: "SELF", Status: st("5001", "0"), Cmdline: sp("heimdalld")}}, Terminal: true},
		{Procs: []GuardProc{{PID: "SELF", Status: sp("Name:\tx\nUid:\t0\n"), Cmdline: sp("heimdalld")}}, Terminal: true},
		{Procs: []GuardProc{{PID: "SELF", Status: sp("PPid:\tnot a number\n"), Cmdline: sp("heimdalld")}}, Terminal: true},
		{Procs: []GuardProc{{PID: "SELF", Status: st("5001", "0"), Cmdline: sp("heimdalld")}, {PID: "5001", Status: st("1", "0"), Exe: "/opt/x/sarina (deleted)", Cmdline: sp("python3")}}, Terminal: true},
		{Procs: []GuardProc{{PID: "SELF", Status: st("5001", "0"), Cmdline: sp("heimdalld")}, {PID: "5001", Status: st("1", "0"), Exe: "/usr/bin/sarina-service", Cmdline: nil}}, Terminal: true},
		{Procs: []GuardProc{{PID: "SELF", Status: st("5001", "0"), Cmdline: sp("heimdalld")}, {PID: "5001", Status: st("1", "0"), Exe: "/usr/bin/sarinax", Cmdline: sp("")}}, Terminal: true},
	}
	// a chain longer than 64: the 65th is not looked at
	var long []string
	for i := 0; i < 70; i++ {
		long = append(long, "p"+strconv.Itoa(i))
	}
	long[66] = "sarina"
	cases = append(cases, GuardCase{Procs: chain(long...), Terminal: true})
	long[66], long[63] = "p66", "sarina"
	cases = append(cases, GuardCase{Procs: chain(long...), Terminal: true})
	self := strconv.Itoa(os.Getpid())
	for i := range cases {
		c := &cases[i]
		root := tmp()
		for _, p := range c.Procs {
			pid := strings.ReplaceAll(p.PID, "SELF", self)
			d := filepath.Join(root, pid)
			if err := os.MkdirAll(d, 0o755); err != nil {
				return nil, err
			}
			if p.Status != nil {
				if err := os.WriteFile(filepath.Join(d, "status"), []byte(*p.Status), 0o644); err != nil {
					return nil, err
				}
			}
			if p.Cmdline != nil {
				if err := os.WriteFile(filepath.Join(d, "cmdline"), []byte(*p.Cmdline), 0o644); err != nil {
					return nil, err
				}
			}
			if p.Exe != "" {
				if err := os.Symlink(p.Exe, filepath.Join(d, "exe")); err != nil {
					return nil, err
				}
			}
		}
		if err := grants.Guard(root, c.Terminal); err != nil {
			c.Error = strings.ReplaceAll(strings.ReplaceAll(err.Error(), root, "PROC"), self, "SELF")
		}
	}
	return cases, nil
}
