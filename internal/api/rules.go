package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/immunity"
)

// SetRules serves the drafting side of immunity's YARA rules: POST /v1/rules/drafts keeps a draft for a held sample
// ({"sample_sha256", "rule", "note"}) after checking its form (the answer carries the lint's and YARA-X's "warnings"
// when there are any), and raises an alert naming the owner's next command;
// GET /v1/rules/drafts lists the drafts. Testing needs the sample (root) and approving needs the owner, so neither is here.
func (s *Server) SetRules(r immunity.Rules, held func() []immunity.Entry, sink alert.Sink) {
	s.mux.HandleFunc("/v1/rules/drafts", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			rs, err := r.Load()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if rs == nil {
				rs = []immunity.Rule{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rs)
		case http.MethodPost:
			req.Body = http.MaxBytesReader(w, req.Body, 32*1024)
			var in struct {
				Sample string `json:"sample_sha256"`
				Rule   string `json:"rule"`
				Note   string `json:"note"`
			}
			if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
				http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
				return
			}
			known := false
			for _, e := range held() {
				known = known || e.SHA256 == in.Sample
			}
			if !known {
				http.Error(w, "sample_sha256 is not a sample Heimdall holds (GET /v1/quarantine)", http.StatusBadRequest)
				return
			}
			uid, _ := PeerUID(req)
			d, err := r.Draft(in.Sample, in.Rule, in.Note, uid, time.Now())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if sink != nil {
				_ = sink.Write(alert.FromFinding(detect.Finding{DetectorID: "rule-draft", Severity: detect.SeverityInfo,
					Summary: "a YARA rule (" + d.Name + ") was drafted for the held sample " + d.SampleSHA[:12] + "; test it: sudo heimdalld immunity rule test " + d.ID,
					Event: detect.Event{Source: "immunity", Kind: "rule_draft", Time: time.Now(),
						Fields: map[string]string{"rule_id": d.ID, "rule": d.Name, "sample": d.SampleSHA, "uid": itoa(uid)}}}))
			}
			w.Header().Set("Content-Type", "application/json")
			out := map[string]any{"id": d.ID, "status": d.Status, "next": "sudo heimdalld immunity rule test " + d.ID}
			if len(d.Warnings) > 0 {
				out["warnings"] = d.Warnings // the lint's and YARA-X's notes; the draft is kept anyway
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
