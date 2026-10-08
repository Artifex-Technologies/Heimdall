package api

import (
	"encoding/json"
	"net/http"

	"github.com/Artifex-Technologies/Heimdall/internal/governance"
)

// maxReviewBodyBytes bounds a /v1/review request body. Memory entries
// Sarina reviews are already bounded (sarina/memory_runtime.py's
// MAX_ENTRY_CHARS), so a legitimate request is small; this is a basic
// safety cap, not a tuned limit -- see internal/governance for the actual
// review logic.
const maxReviewBodyBytes = 64 * 1024

// handleReview implements POST /v1/review, Heimdall's one write/action
// endpoint (see package doc comment). A missing reviewer (this server was
// constructed without one) or a malformed/empty request both fail closed
// with an HTTP error rather than silently answering "allow" -- a caller
// that gets a non-2xx response is unambiguously told not to treat that as
// a clean bill of health.
func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}
	if s.reviewer == nil {
		http.Error(w, "governance review is not enabled on this server", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxReviewBodyBytes)
	var req governance.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Text == "" {
		http.Error(w, "text is required", http.StatusBadRequest)
		return
	}

	verdict := s.reviewer.Review(req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(verdict)
}
