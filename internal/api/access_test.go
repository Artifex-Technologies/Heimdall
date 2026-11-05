package api

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
)

// The client end of a loopback connection is found in the kernel's table by its address and the server's, and names its
// owner; the server's own end (same two addresses swapped) must not be taken for it.
func TestLookupPeerFindsTheClientEnd(t *testing.T) {
	dir := t.TempDir()
	tcp := filepath.Join(dir, "tcp")
	// 127.0.0.1:8930 <-> 127.0.0.1:54321 (0xD431): the server's socket (uid 950) first, the client's (uid 1000) second.
	body := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:22E2 0100007F:D431 01 00000000:00000000 00:00000000 00000000   950        0 111 1\n" +
		"   1: 0100007F:D431 0100007F:22E2 01 00000000:00000000 00:00000000 00000000  1000        0 222 1\n"
	if err := os.WriteFile(tcp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	uid, err := lookupPeer([]string{tcp}, hostPort{net.ParseIP("127.0.0.1"), 54321}, hostPort{net.ParseIP("127.0.0.1"), 8930})
	if err != nil || uid != 1000 {
		t.Fatalf("got %d, %v; want 1000", uid, err)
	}
	if _, err := lookupPeer([]string{tcp}, hostPort{net.ParseIP("127.0.0.1"), 1}, hostPort{net.ParseIP("127.0.0.1"), 8930}); err == nil {
		t.Fatal("an unknown connection must not be identified")
	}
}

func TestAccessPolicy(t *testing.T) {
	members := map[uint32]bool{1000: true, 954: true}
	cases := []struct {
		name string
		uid  uint32
		err  error
		want int
		path string
	}{
		{"owner (wheel)", 1000, nil, http.StatusOK, "/v1/alerts"},
		{"sarina", 954, nil, http.StatusOK, "/v1/alerts"},
		{"root", 0, nil, http.StatusOK, "/v1/alerts"},
		{"another account", 1001, nil, http.StatusForbidden, "/v1/alerts"},
		{"another account, review", 1001, nil, http.StatusForbidden, "/v1/review"},
		{"unidentified", 0, errors.New("not in table"), http.StatusForbidden, "/v1/alerts"},
		{"health is open to all", 1001, nil, http.StatusOK, "/healthz"},
	}
	for _, c := range cases {
		s := NewServer(alert.NewRing(10), nil)
		uid, err := c.uid, c.err
		s.SetAccess(&Access{
			PeerUID: func(*http.Request) (uint32, error) { return uid, err },
			Member:  func(u uint32) bool { return members[u] },
		})
		r := httptest.NewRequest(http.MethodGet, c.path, nil)
		r.Host = "127.0.0.1:8930"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, w.Code, c.want)
		}
	}
}

// End to end on a real loopback socket: the test's own account (the same as the server's, so always allowed) is identified
// from the kernel's table, and a policy that refuses everyone else still lets it in, while one that sees a different
// account refuses.
func TestRealLoopbackPeerIsIdentified(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		t.Skip("no /proc/net/tcp")
	}
	var seen uint32 = 99999
	s := NewServer(alert.NewRing(10), nil)
	s.SetAccess(&Access{
		PeerUID: func(r *http.Request) (uint32, error) {
			u, err := procPeerUID(r)
			seen = u
			return u, err
		},
		Member: func(uint32) bool { return false },
	})
	srv := httptest.NewServer(s)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/alerts")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || seen != uint32(os.Getuid()) {
		t.Fatalf("status %d, peer %d, want 200 and %d", resp.StatusCode, seen, os.Getuid())
	}
}
