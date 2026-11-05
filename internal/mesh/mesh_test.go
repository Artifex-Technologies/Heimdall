package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

type capture struct {
	mu  sync.Mutex
	got []alert.Alert
}

func (c *capture) Write(a alert.Alert) error {
	c.mu.Lock()
	c.got = append(c.got, a)
	c.mu.Unlock()
	return nil
}
func (c *capture) all() []alert.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]alert.Alert(nil), c.got...)
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type inst struct {
	node       *Node
	local, out *capture
	addr       string
	peers      string
}

func newInst(t *testing.T) *inst {
	dir := t.TempDir()
	id, err := LoadOrCreate(filepath.Join(dir, "mesh"))
	if err != nil {
		t.Fatal(err)
	}
	i := &inst{local: &capture{}, out: &capture{}, addr: freeAddr(t), peers: filepath.Join(dir, "peers.json")}
	i.node = &Node{ID: id, PeersPath: i.peers, Listen: i.addr, Next: i.local, Out: i.out, MinSeverity: detect.SeverityWarning}
	return i
}

func enroll(t *testing.T, on *inst, name string, other *inst) {
	if _, err := SetPeer(on.peers, Peer{Name: name, Fingerprint: other.node.ID.Fingerprint, Address: other.addr}, false); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, c *capture, n int) []alert.Alert {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.all(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("wanted %d alerts, got %d", n, len(c.all()))
	return nil
}

func TestTwoEnrolledInstancesShareAlerts(t *testing.T) {
	a, b := newInst(t), newInst(t)
	enroll(t, a, "desk", b)
	enroll(t, b, "laptop", a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, i := range []*inst{a, b} {
		if err := i.node.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	a.node.Write(alert.Alert{Time: time.Now(), DetectorID: "remote-access", Severity: detect.SeverityCritical, Summary: "chisel found",
		EventText: "SECRET session text", Fields: map[string]string{"path": "/home/x/.local/bin/updater"}})
	a.node.Write(alert.Alert{DetectorID: "connection-watch", Severity: detect.SeverityInfo, Summary: "info stays home"})
	got := waitFor(t, b.out, 1)
	r := got[0]
	if r.DetectorID != DetectorID || r.Severity != detect.SeverityCritical || r.Summary != "[laptop] chisel found" || r.Fields["peer"] != "laptop" {
		t.Fatalf("%+v", r)
	}
	if r.EventText != "" || r.Fields["path"] != "" {
		t.Fatal("only the summary and labels travel, never the event's text or fields")
	}
	if len(a.local.all()) != 2 {
		t.Fatal("every local alert still reaches the local outputs")
	}
	// a received alert is never sent on (B's node forwards only local ones)
	b.node.Write(r)
	time.Sleep(300 * time.Millisecond)
	if len(a.out.all()) != 0 {
		t.Fatal("a received alert went back out: loops and relaying must be impossible")
	}
}

func TestUnenrolledKeysAreCutInTheHandshake(t *testing.T) {
	a, b, stranger := newInst(t), newInst(t), newInst(t)
	enroll(t, b, "laptop", a) // B accepts A only
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.node.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// the stranger believes B is its peer and tries to send
	enroll(t, stranger, "desk", b)
	if err := stranger.node.Start(ctx); err != nil {
		t.Fatal(err)
	}
	stranger.node.Write(alert.Alert{DetectorID: "remote-access", Severity: detect.SeverityCritical, Summary: "fake"})
	time.Sleep(500 * time.Millisecond)
	if len(b.out.all()) != 0 {
		t.Fatal("an unenrolled key delivered an alert")
	}
	// and a plain TLS client without any certificate gets nothing either
	cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if resp, err := cl.Post("https://"+b.addr+Path, "application/json", bytes.NewReader([]byte(`{"alerts":[{"summary":"x","severity":"critical"}]}`))); err == nil {
		resp.Body.Close()
		t.Fatalf("a client without a key got an answer: %s", resp.Status)
	}
	// a client that dials A's address but finds another key there refuses to send to it
	if _, err := SetPeer(a.peers, Peer{Name: "desk", Fingerprint: stranger.node.ID.Fingerprint, Address: b.addr}, false); err != nil {
		t.Fatal(err)
	}
	a.node.Listen = ""
	if err := a.node.Start(ctx); err != nil {
		t.Fatal(err)
	}
	a.node.Write(alert.Alert{DetectorID: "remote-access", Severity: detect.SeverityCritical, Summary: "meant for the stranger"})
	time.Sleep(500 * time.Millisecond)
	if len(b.out.all()) != 0 {
		t.Fatal("an alert went to a computer whose key is not the one enrolled for that address")
	}
}

func TestReceiveLimits(t *testing.T) {
	b := newInst(t)
	if got := received("desk", Wire{Severity: "root", Summary: strings.Repeat("x", 2000), DetectorID: strings.Repeat("d", 100)}); got.Severity != detect.SeverityInfo || len(got.Summary) > maxSummary+20 || len(got.Fields["remote_detector"]) != 40 {
		t.Fatalf("%+v", got)
	}
	lim := &bucket{level: ratePerMin, last: time.Now()}
	n := 0
	for lim.take() {
		n++
	}
	if n != ratePerMin {
		t.Fatalf("burst %d", n)
	}
	for _, bad := range []Peer{
		{Name: "Desk", Fingerprint: b.node.ID.Fingerprint, Address: "127.0.0.1:1"},
		{Name: "desk", Fingerprint: "hm1-short", Address: "127.0.0.1:1"},
		{Name: "desk", Fingerprint: b.node.ID.Fingerprint, Address: "desk.lan:8931"},
		{Name: "desk", Fingerprint: b.node.ID.Fingerprint, Address: "0.0.0.0:8931"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
	b.node.Listen = "0.0.0.0:0"
	if err := b.node.Start(context.Background()); err == nil {
		t.Fatal("listening on every address must be refused")
	}
}
