package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
)

// A web page reaches 127.0.0.1 only through DNS rebinding (its own Host header) or as a cross-site request (Origin,
// Sec-Fetch-Site): both are refused; Heimdall's own clients send a loopback Host and no browser headers.
func TestOnlyLoopbackNonBrowserRequestsAreServed(t *testing.T) {
	s := NewServer(alert.NewRing(10), nil)
	cases := []struct {
		host   string
		header map[string]string
		want   int
	}{
		{"127.0.0.1:8930", nil, http.StatusOK},
		{"localhost:8930", nil, http.StatusOK},
		{"[::1]:8930", nil, http.StatusOK},
		{"attacker.example:8930", nil, http.StatusForbidden},
		{"attacker.example", nil, http.StatusForbidden},
		{"192.168.1.20:8930", nil, http.StatusForbidden},
		{"127.0.0.1:8930", map[string]string{"Origin": "http://attacker.example"}, http.StatusForbidden},
		{"127.0.0.1:8930", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		r.Host = c.host
		for k, v := range c.header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("host %q headers %v: got %d, want %d", c.host, c.header, w.Code, c.want)
		}
	}
}
