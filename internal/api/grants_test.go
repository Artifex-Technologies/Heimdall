package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/grants"
)

// An agent files a request: the account comes from the kernel (here the injected peer), never the body; the owner is
// alerted with the command that decides it; nothing is approved and the decisions file is never created by the daemon.
func TestRequestsAreFiledNeverApproved(t *testing.T) {
	dir := t.TempDir()
	st := grants.Store{Requests: filepath.Join(dir, "req.json"), Decisions: filepath.Join(dir, "grants.json")}
	ring := alert.NewRing(10)
	s := NewServer(ring, nil)
	s.SetAccess(&Access{PeerUID: func(*http.Request) (uint32, error) { return 954, nil }, Member: func(uint32) bool { return true }})
	s.SetGrants(st, ring)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/requests", strings.NewReader(body))
		r.Host = "127.0.0.1:8930"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := post(`{"kind":"escalation","detail":"claude-cli","session_id":"s1","reason":"the local model failed","uid":0,"status":"approved"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["status"] != "pending" || !strings.Contains(out["approve"].(string), "sudo heimdalld grant approve") {
		t.Fatalf("%v", out)
	}
	p, _ := st.Pending()
	if len(p) != 1 || p[0].UID != 954 {
		t.Fatalf("the account must be the kernel's (954), not the body's: %+v", p)
	}
	if _, on, _ := st.Load(); on {
		t.Fatal("the daemon must never write the decisions file")
	}
	a := ring.Recent(1)
	if len(a) != 1 || a[0].DetectorID != "grant-request" || a[0].Severity != "warning" {
		t.Fatalf("%+v", a)
	}
	if w := post(`{"kind":"root","detail":"everything"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown kind must be refused: %d", w.Code)
	}
}
