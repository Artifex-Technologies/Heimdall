package detect

import "testing"

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
