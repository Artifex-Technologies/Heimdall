package detect

import (
	"strings"
	"testing"
)

func limboEv(kind, guest string, extra map[string]string) Event {
	f := map[string]string{"guest": guest}
	for k, v := range extra {
		f[k] = v
	}
	return Event{Source: "limbo", Kind: kind, Fields: f}
}

func TestLimboGuestDetectorSequences(t *testing.T) {
	cases := []struct {
		name     string
		events   []Event
		wantSev  []Severity // severities of findings, in order
		wantInfo string
	}{
		{
			name: "normal lifecycle is silent",
			events: []Event{
				limboEv("guest.define", "lab", nil), limboEv("policy.apply", "lab", nil),
				limboEv("guest.start", "lab", nil), limboEv("app.launch", "lab", nil),
				limboEv("guest.stop", "lab", nil), limboEv("policy.remove", "lab", nil),
			},
		},
		{
			name:    "start without policy",
			events:  []Event{limboEv("guest.start", "lab", nil)},
			wantSev: []Severity{SeverityCritical},
		},
		{
			name: "policy removed under a running guest",
			events: []Event{
				limboEv("policy.apply", "lab", nil), limboEv("guest.start", "lab", nil),
				limboEv("policy.remove", "lab", nil),
			},
			wantSev: []Severity{SeverityCritical},
		},
		{
			name: "rollback after failed up is silent",
			events: []Event{
				limboEv("policy.apply", "lab", nil), limboEv("policy.remove", "lab", nil),
			},
		},
		{
			name: "guests are tracked independently",
			events: []Event{
				limboEv("policy.apply", "a", nil), limboEv("guest.start", "b", nil),
			},
			wantSev: []Severity{SeverityCritical},
		},
		{
			name: "restart after stop needs policy again",
			events: []Event{
				limboEv("policy.apply", "lab", nil), limboEv("guest.start", "lab", nil),
				limboEv("guest.stop", "lab", nil), limboEv("policy.remove", "lab", nil),
				limboEv("guest.start", "lab", nil),
			},
			wantSev: []Severity{SeverityCritical},
		},
		{
			name:    "image rejected",
			events:  []Event{limboEv("image.rejected", "lab", map[string]string{"reason": "mismatch"})},
			wantSev: []Severity{SeverityCritical},
		},
		{
			name:    "image rejected by the weekly check",
			events:  []Event{limboEv("image.rejected", "", map[string]string{"reason": "mismatch", "path": "/var/lib/limbo/images/arch.qcow2", "during": "weekly check"})},
			wantSev: []Severity{SeverityCritical},
		},
		{
			name:    "license gate",
			events:  []Event{limboEv("gate.blocked", "lab", nil)},
			wantSev: []Severity{SeverityWarning},
		},
		{
			name:   "other sources ignored",
			events: []Event{{Source: "agent-session", Kind: "guest.start", Fields: map[string]string{"guest": "lab"}}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := NewLimboGuestDetector()
			var got []Severity
			for _, e := range c.events {
				for _, f := range d.Inspect(e) {
					got = append(got, f.Severity)
				}
			}
			if len(got) != len(c.wantSev) {
				t.Fatalf("got %v, want %v", got, c.wantSev)
			}
			for i := range got {
				if got[i] != c.wantSev[i] {
					t.Fatalf("got %v, want %v", got, c.wantSev)
				}
			}
		})
	}
}

func TestTheWeeklyImageCheckNamesTheImage(t *testing.T) {
	d := NewLimboGuestDetector()
	fs := d.Inspect(limboEv("image.rejected", "", map[string]string{"reason": "mismatch", "path": "/var/lib/limbo/images/arch.qcow2", "during": "weekly check"}))
	if len(fs) != 1 || !strings.Contains(fs[0].Summary, `"/var/lib/limbo/images/arch.qcow2"`) || !strings.Contains(fs[0].Summary, "weekly check") || strings.Contains(fs[0].Summary, `guest ""`) {
		t.Fatalf("got %+v", fs)
	}
}

// HEI-10: limbo wine's wine.start names the program file's SHA-256; a file whose content the immunity store holds as
// malware is critical, a suspect a warning, a released one (judged good) or an unknown one nothing.
func TestLimboGuestDetectorWineRunOfAHeldSample(t *testing.T) {
	sha := func(c string) string { return strings.Repeat(c, 64) }
	store := map[string]string{sha("a"): "held", sha("b"): "immune", sha("c"): "reference", sha("d"): "suspect", sha("e"): "released"}
	d := NewLimboGuestDetector().WithSamples(func(s string) string { return store[s] })
	run := func(s string) []Finding {
		return d.Inspect(limboEv("wine.start", "wine:apps", map[string]string{
			"prefix": "apps", "program": "C:\\setup.exe", "via": "cli", "run": "r1", "network": "none", "sha256": s,
		}))
	}
	cases := []struct {
		sha  string
		want Severity
	}{
		{sha("a"), SeverityCritical}, {sha("b"), SeverityCritical}, {sha("c"), SeverityCritical},
		{sha("d"), SeverityWarning}, {sha("e"), ""}, {sha("f"), ""}, {"", ""}, {"short", ""},
	}
	for _, tc := range cases {
		got := run(tc.sha)
		if tc.want == "" {
			if len(got) != 0 {
				t.Errorf("%q: want nothing, got %v", tc.sha, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Severity != tc.want {
			t.Fatalf("%q: want one %s, got %v", tc.sha, tc.want, got)
		}
		if s := got[0].Summary; !strings.Contains(s, `"C:\\setup.exe"`) || !strings.Contains(s, `"apps"`) || !strings.Contains(s, tc.sha) {
			t.Errorf("the summary names the program, the prefix and the hash: %s", s)
		}
	}
	// without the store (a scan with no immunity), Wine runs are not looked up
	if f := NewLimboGuestDetector().Inspect(limboEv("wine.start", "wine:apps", map[string]string{"sha256": sha("a")})); len(f) != 0 {
		t.Errorf("no store, no finding: %v", f)
	}
}
