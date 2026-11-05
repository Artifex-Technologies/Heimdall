package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/immunity"
)

func TestRuleDraftsOnlyForHeldSamples(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	r := immunity.Rules{Path: filepath.Join(t.TempDir(), "drafts.json")}
	ring := alert.NewRing(10)
	s := NewServer(ring, nil)
	s.SetAccess(&Access{PeerUID: func(*http.Request) (uint32, error) { return 954, nil }, Member: func(uint32) bool { return true }})
	s.SetRules(r, func() []immunity.Entry { return []immunity.Entry{{SHA256: sha}} }, ring)
	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/rules/drafts", strings.NewReader(body))
		req.Host = "127.0.0.1:8930"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w.Code
	}
	rule := `rule Heimdall_demo\n{\n  strings:\n    $a = \"marker\"\n  condition:\n    $a\n}\n`
	if c := post(`{"sample_sha256":"` + strings.Repeat("cd", 32) + `","rule":"` + rule + `"}`); c != http.StatusBadRequest {
		t.Fatalf("a sample Heimdall does not hold: %d", c)
	}
	if c := post(`{"sample_sha256":"` + sha + `","rule":"include \"/etc/shadow\"\n` + rule + `"}`); c != http.StatusBadRequest {
		t.Fatalf("an include must be refused: %d", c)
	}
	if c := post(`{"sample_sha256":"` + sha + `","rule":"` + rule + `","note":"from the triage"}`); c != http.StatusOK {
		t.Fatalf("%d", c)
	}
	rs, _ := r.Load()
	if len(rs) != 1 || rs[0].UID != 954 || rs[0].Status != immunity.RuleDraft {
		t.Fatalf("%+v", rs)
	}
	if a := ring.Recent(1); len(a) != 1 || a[0].DetectorID != "rule-draft" {
		t.Fatalf("%+v", a)
	}
}
