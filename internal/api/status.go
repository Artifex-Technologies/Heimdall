// Package api serves a small loopback-only HTTP API, following the
// ecosystem's shared "loopback only, no ecosystem service binds a routable
// interface by default" convention (docs/ECOSYSTEM.md in Sarina). Every
// endpoint but one is read-only by construction, reporting on state that
// already exists. The one exception is POST /v1/review (Phase 4,
// internal/governance): a sibling process's behavior can depend on its
// response, and a review is itself recorded as an alert. See
// governance.Reviewer's doc comment for why that's a deliberate, narrow
// exception rather than a precedent for more write endpoints here.
package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/governance"
)

// Server exposes GET /healthz (liveness), GET /v1/alerts?n=N (the N most
// recent alerts, newest first; default and max 500), and POST /v1/review
// (Phase 4 governance consultation; see package doc comment).
type Server struct {
	ring     *alert.Ring
	reviewer *governance.Reviewer
	mux      *http.ServeMux
}

func NewServer(ring *alert.Ring, reviewer *governance.Reviewer) *Server {
	s := &Server{ring: ring, reviewer: reviewer, mux: http.NewServeMux()}
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/v1/alerts", s.handleAlerts)
	s.mux.HandleFunc("/v1/review", s.handleReview)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	n := 50
	if raw := r.URL.Query().Get("n"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n > 500 {
		n = 500
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.ring.Recent(n))
}

// ListenAndServeLoopback refuses to bind anything but a loopback address,
// so a misconfigured api_addr in config fails loudly at startup instead of
// quietly exposing the alert feed to the network.
func ListenAndServeLoopback(addr string, handler http.Handler) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return &net.AddrError{Err: "heimdalld: api_addr must be a loopback address", Addr: addr}
	}
	return http.ListenAndServe(addr, handler)
}
