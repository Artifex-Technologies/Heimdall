package grants

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func store(t *testing.T) Store {
	d := t.TempDir()
	return Store{Requests: filepath.Join(d, "requests.json"), Decisions: filepath.Join(d, "grants.json")}
}

func TestValidate(t *testing.T) {
	bad := []Request{
		{Kind: "root", Detail: "x"},
		{Kind: KindEscalation},
		{Kind: KindEscalation, Detail: "../../etc"},
		{Kind: KindAccessTier, Detail: "4"},
		{Kind: KindAccessTier, Detail: "0"},
	}
	for _, r := range bad {
		if Validate(r) == nil {
			t.Errorf("%+v should be refused", r)
		}
	}
	for _, r := range []Request{{Kind: KindEscalation, Detail: "claude-cli"}, {Kind: KindAccessTier, Detail: "3"}} {
		if err := Validate(r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
}

func TestFileMergesRepeatsAndDecideApprovesOnce(t *testing.T) {
	s := store(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	a, err := s.File(Request{Kind: KindEscalation, Detail: "claude-cli", SessionID: "s1", UID: 1000, Reason: "stuck"}, now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.File(Request{Kind: KindEscalation, Detail: "claude-cli", SessionID: "s1", UID: 1000}, now)
	if a.ID != b.ID || b.Count != 2 {
		t.Fatalf("a repeat must merge: %+v %+v", a, b)
	}
	if _, ok, _ := s.Load(); ok {
		t.Fatal("filing a request must never create the decisions file")
	}
	if _, err := s.Decide(a.ID, true, "owner", 48*time.Hour, now); err == nil {
		t.Fatal("an approval longer than a day must be refused")
	}
	if _, err := s.Decide(a.ID, true, "owner", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	d, ok, _ := s.Load()
	if !ok || !d.EscalationAllowed("claude-cli", "s1", now.Add(30*time.Minute)) {
		t.Fatalf("approved hand-off not allowed: %+v", d)
	}
	if d.EscalationAllowed("claude-cli", "s2", now) || d.EscalationAllowed("claude", "s1", now) || d.EscalationAllowed("claude-cli", "s1", now.Add(2*time.Hour)) {
		t.Fatal("an approval covers its tier, its session and its time only")
	}
	if _, err := s.Decide(a.ID, true, "owner", time.Hour, now); err == nil {
		t.Fatal("a decided request is no longer open")
	}
	if p, _ := s.Pending(); len(p) != 0 {
		t.Fatalf("pending %+v", p)
	}
}

func TestAccessTierDecisions(t *testing.T) {
	s := store(t)
	now := time.Now()
	r, _ := s.File(Request{Kind: KindAccessTier, Detail: "2", UID: 954}, now)
	if _, err := s.Decide(r.ID, false, "owner", 0, now); err != nil {
		t.Fatal(err)
	}
	d, _, _ := s.Load()
	if d.AccessTier != nil || len(d.History) != 1 || d.History[0].Status != StatusDenied {
		t.Fatalf("a denial changes no tier: %+v", d)
	}
	if err := s.SetTier(1, "owner", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTier(4, "owner", now); err == nil {
		t.Fatal("tier 4 is not set here")
	}
	d, _, _ = s.Load()
	if d.AccessTier == nil || *d.AccessTier != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestPendingListIsBounded(t *testing.T) {
	s := store(t)
	for i := 0; i < maxPending+10; i++ {
		if _, err := s.File(Request{Kind: KindEscalation, Detail: "t" + strconv.Itoa(i)}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if p, _ := s.Pending(); len(p) != maxPending {
		t.Fatalf("%d pending", len(p))
	}
}

// fakeProc builds /proc entries for this process and its made-up ancestors: chain[0] is our parent.
func fakeProc(t *testing.T, chain []struct {
	pid int
	exe string
	uid string
}) string {
	root := t.TempDir()
	mk := func(pid, ppid int, exe, uid string) {
		dir := filepath.Join(root, strconv.Itoa(pid))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tx\nPPid:\t"+strconv.Itoa(ppid)+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "cmdline"), []byte(exe+"\x00--flag\x00"), 0o644)
		os.Symlink(exe, filepath.Join(dir, "exe"))
	}
	next := 1
	if len(chain) > 0 {
		next = chain[0].pid
	}
	mk(os.Getpid(), next, "/usr/bin/heimdalld", "0")
	for i, c := range chain {
		p := 1
		if i+1 < len(chain) {
			p = chain[i+1].pid
		}
		mk(c.pid, p, c.exe, c.uid)
	}
	return root
}

func TestGuard(t *testing.T) {
	type p = struct {
		pid int
		exe string
		uid string
	}
	clean := fakeProc(t, []p{{50, "/usr/bin/sudo", "0"}, {40, "/usr/bin/bash", "1000"}, {30, "/usr/bin/ghostty", "1000"}})
	if err := Guard(clean, true); err != nil {
		t.Fatalf("the owner at a terminal must be able to decide: %v", err)
	}
	if err := Guard(clean, false); err == nil {
		t.Fatal("no terminal: refused")
	}
	viaSarina := fakeProc(t, []p{{50, "/usr/bin/sudo", "0"}, {40, "/usr/bin/bash", "1000"}, {35, "/usr/bin/sarina", "1000"}, {30, "/usr/bin/ghostty", "1000"}})
	if err := Guard(viaSarina, true); err == nil {
		t.Fatal("a command started under Sarina's CLI must be refused")
	}
	t.Setenv("SUDO_USER", "sarina")
	if err := Guard(clean, true); err == nil {
		t.Fatal("sudo by the sarina account must be refused")
	}
}
