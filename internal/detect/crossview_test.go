package detect

import (
	"strings"
	"testing"
)

func TestCrossViewIsCritical(t *testing.T) {
	d := NewCrossViewDetector()
	for _, tc := range []struct {
		kind string
		want int
	}{{"crossview", 1}, {"remote_access", 0}} {
		got := d.Inspect(Event{Kind: tc.kind, Text: "process 4242 (kworkerd) runs but /proc does not list it", Fields: map[string]string{"what": "process"}})
		if len(got) != tc.want {
			t.Fatalf("%s: %d findings", tc.kind, len(got))
		}
		if tc.want == 1 && (got[0].Severity != SeverityCritical || !strings.Contains(got[0].Summary, "rootkit")) {
			t.Errorf("%+v", got[0])
		}
	}
}
