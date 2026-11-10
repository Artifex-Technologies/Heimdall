package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The Rust port reads the text detectors' patterns from a rule file (rust/heimdall/rules/text.json). It must hold exactly
// these patterns, in this order, with these words, so both daemons look for the same things; change both together.
func TestRustRuleFileMatchesGoPatterns(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "rust", "heimdall", "rules", "text.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rules []struct {
			Detector string   `json:"detector"`
			Pattern  string   `json:"pattern"`
			Needs    []string `json:"needs"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	type rule struct {
		pattern string
		needs   []string
	}
	var got, want []rule
	for _, r := range f.Rules {
		got = append(got, rule{r.Detector + " " + r.Pattern, r.Needs})
	}
	for i, p := range injectionPatterns {
		want = append(want, rule{"injection-phrase " + p.String(), injectionLiterals[i].any})
	}
	for i, p := range credentialPatterns {
		want = append(want, rule{"credential-shape " + p.String(), credentialLiterals[i].any})
	}
	if !reflect.DeepEqual(got, want) {
		for i := range want {
			if i >= len(got) || !reflect.DeepEqual(got[i], want[i]) {
				t.Errorf("rule %d: the Rust file has %+v, Go has %+v", i+1, got[min(i, len(got)-1)], want[i])
			}
		}
		t.Fatalf("%d rules in the Rust file, %d in Go", len(got), len(want))
	}
}
