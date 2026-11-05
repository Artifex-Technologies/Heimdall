package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/grants"
)

// SetGrants serves the agent's side of the grant gate (internal/grants): POST /v1/requests files a request (escalation to
// another model tier, or a higher access tier) and raises an alert so the owner sees it; GET /v1/requests lists the open ones
// and the owner's recent decisions. Nothing here can approve: decisions are written by root (`heimdalld grant`), and the agent
// reads them from the root-owned file, not from this API.
func (s *Server) SetGrants(st grants.Store, sink alert.Sink) {
	s.mux.HandleFunc("/v1/requests", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pending, err := st.Pending()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			d, on, _ := st.Load()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"gate_on": on, "pending": grants.Sorted(pending), "decisions": d})
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
			var req grants.Request
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
				return
			}
			req.ID, req.Count = "", 0
			req.UID, _ = PeerUID(r) // the kernel's word, never the body's
			filed, err := st.File(req, time.Now())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			approve := "sudo heimdalld grant approve " + filed.ID
			if sink != nil {
				_ = sink.Write(alert.FromFinding(detect.Finding{DetectorID: "grant-request", Severity: detect.SeverityWarning,
					Summary: "an AI agent asks for " + describe(filed) + "; only you can allow it: " + approve + " (or deny)",
					Event: detect.Event{Source: "governance-request", Kind: "grant_request", SessionID: filed.SessionID, Time: time.Now(), Text: filed.Reason,
						Fields: map[string]string{"request_id": filed.ID, "kind": filed.Kind, "detail": filed.Detail, "uid": itoa(filed.UID)}}}))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": filed.ID, "status": grants.StatusPending, "count": filed.Count, "approve": approve})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func describe(r grants.Request) string {
	if r.Kind == grants.KindAccessTier {
		return "access tier " + r.Detail
	}
	return "handing the conversation to the model tier " + r.Detail
}

func itoa(u uint32) string { b, _ := json.Marshal(u); return string(b) }
