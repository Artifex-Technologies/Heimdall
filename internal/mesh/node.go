package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

const (
	DetectorID = "mesh" // alerts received from a peer
	Path       = "/mesh/v1/alerts"

	maxBody      = 64 << 10
	maxBatch     = 50
	maxSummary   = 500
	queueLen     = 256
	ratePerMin   = 120 // alerts a peer may send per minute (burst the same)
	backoffFirst = 5 * time.Second
	backoffMax   = 5 * time.Minute
)

// Wire is one alert as it travels: the summary and labels only, never the event's text or fields (they may quote a
// session or a file).
type Wire struct {
	Time       time.Time `json:"time"`
	DetectorID string    `json:"detector_id"`
	Severity   string    `json:"severity"`
	Summary    string    `json:"summary"`
	Source     string    `json:"source"`
}

type batch struct {
	Alerts []Wire `json:"alerts"`
}

// Node is this instance's place in the mesh: a sink that forwards local alerts to every enrolled peer, and (with Listen) a
// TLS listener that takes alerts from them and writes them to Out.
type Node struct {
	ID          Identity
	PeersPath   string
	Listen      string     // ip:port; empty: receive nothing
	Next        alert.Sink // local alerts go on here first
	Out         alert.Sink // received alerts are written here (the outputs only, never containment or quarantine)
	MinSeverity detect.Severity
	Log         *log.Logger

	mu     sync.Mutex
	queues map[string]chan Wire
	limits map[string]*bucket
	cert   tls.Certificate
	ready  bool
	// Dropped counts alerts not sent because a peer's queue was full (it has been unreachable for long).
	Dropped int
}

func (n *Node) logf(format string, a ...any) {
	if n.Log != nil {
		n.Log.Printf("mesh: "+format, a...)
	}
}

func rank(s string) int {
	switch s {
	case string(detect.SeverityCritical):
		return 2
	case string(detect.SeverityWarning):
		return 1
	}
	return 0
}

// Write passes the alert on, then queues it for each peer when it is local, at least MinSeverity, and not about the mesh
// itself (a received alert is never sent on: no loops, no relaying).
func (n *Node) Write(a alert.Alert) error {
	err := n.Next.Write(a)
	if a.DetectorID == DetectorID || a.DetectorID == "integration" || rank(string(a.Severity)) < rank(string(n.MinSeverity)) {
		return err
	}
	w := Wire{Time: a.Time, DetectorID: a.DetectorID, Severity: string(a.Severity), Summary: clip(a.Summary), Source: a.Source}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, q := range n.queues {
		select {
		case q <- w:
		default:
			n.Dropped++
		}
	}
	return err
}

func clip(s string) string {
	if len(s) > maxSummary {
		return s[:maxSummary] + "..."
	}
	return s
}

// tlsConfig accepts only a peer whose key is enrolled (want: that one peer, for a client; empty: any enrolled, for the
// server). The peers file is read on every handshake, so `heimdalld mesh forget` takes effect for new connections at once.
func (n *Node) tlsConfig(want string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{n.cert},
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true, // no certificate authority: the key itself is checked below, against the owner's list
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			fp, err := peerFingerprint(raw)
			if err != nil {
				return err
			}
			if want != "" {
				if fp != want {
					return fmt.Errorf("peer key %s is not the enrolled %s", fp, want)
				}
				return nil
			}
			if _, ok := n.peerByFingerprint(fp); !ok {
				return fmt.Errorf("key %s is not enrolled", fp)
			}
			return nil
		},
	}
}

func (n *Node) peerByFingerprint(fp string) (Peer, bool) {
	ps, err := LoadPeers(n.PeersPath)
	if err != nil {
		n.logf("%v", err)
		return Peer{}, false
	}
	for _, p := range ps {
		if p.Fingerprint == fp {
			return p, true
		}
	}
	return Peer{}, false
}

// Start makes the certificate, starts one sender per enrolled peer and, with Listen set, the listener. It returns at once;
// everything stops with ctx.
func (n *Node) Start(ctx context.Context) error {
	cert, err := n.ID.certificate()
	if err != nil {
		return err
	}
	peers, err := LoadPeers(n.PeersPath)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.cert, n.queues, n.limits, n.ready = cert, map[string]chan Wire{}, map[string]*bucket{}, true
	for _, p := range peers {
		if p.Fingerprint == n.ID.Fingerprint {
			continue // itself
		}
		q := make(chan Wire, queueLen)
		n.queues[p.Name] = q
		go n.send(ctx, p, q)
	}
	n.mu.Unlock()
	if n.Listen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(n.Listen)
	if err != nil || net.ParseIP(host) == nil || net.ParseIP(host).IsUnspecified() {
		return errors.New("mesh_listen must be one IP address and port of this computer (not 0.0.0.0 or ::), e.g. the address on your own WireGuard or LAN interface")
	}
	ln, err := net.Listen("tcp", n.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(n.receive), TLSConfig: n.tlsConfig(""), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() { <-ctx.Done(); srv.Close() }()
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			n.logf("listener stopped: %v", err)
		}
	}()
	n.logf("listening on %s for %d enrolled peer(s)", n.Listen, len(peers))
	return nil
}

// receive takes one batch from an enrolled peer (the TLS handshake already proved which).
func (n *Node) receive(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path || r.Method != http.MethodPost || r.TLS == nil {
		http.NotFound(w, r)
		return
	}
	var raw [][]byte
	for _, c := range r.TLS.PeerCertificates {
		raw = append(raw, c.Raw)
	}
	fp, err := peerFingerprint(raw)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p, ok := n.peerByFingerprint(fp)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var b batch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&b); err != nil || len(b.Alerts) > maxBatch {
		http.Error(w, "bad batch", http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	lim := n.limits[p.Name]
	if lim == nil {
		lim = &bucket{level: ratePerMin, last: time.Now()}
		n.limits[p.Name] = lim
	}
	n.mu.Unlock()
	for _, a := range b.Alerts {
		if !lim.take() {
			http.Error(w, "too many alerts", http.StatusTooManyRequests)
			return
		}
		n.Out.Write(received(p.Name, a))
	}
	w.WriteHeader(http.StatusNoContent)
}

// received turns a peer's alert into a local one: labelled with the peer, text bounded, severity kept but never above
// critical, and only the labels it carried (it is the peer's word, shown, never acted on).
func received(peer string, a Wire) alert.Alert {
	sev := detect.SeverityInfo
	switch a.Severity {
	case string(detect.SeverityCritical):
		sev = detect.SeverityCritical
	case string(detect.SeverityWarning):
		sev = detect.SeverityWarning
	}
	det := clipTo(a.DetectorID, 40)
	return alert.FromFinding(detect.Finding{DetectorID: DetectorID, Severity: sev,
		Summary: "[" + peer + "] " + clip(strings.ToValidUTF8(a.Summary, "?")),
		Event: detect.Event{Source: "mesh:" + peer, Kind: "mesh_alert", Time: time.Now(),
			Fields: map[string]string{"peer": peer, "remote_detector": det, "remote_time": a.Time.UTC().Format(time.RFC3339), "remote_source": clipTo(a.Source, 40)}}})
}

func clipTo(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > n {
		return s[:n]
	}
	return s
}

// send delivers one peer's queue: it waits for alerts (no polling), sends up to maxBatch at once, and backs off while the
// peer is unreachable, keeping at most queueLen alerts meanwhile.
func (n *Node) send(ctx context.Context, p Peer, q chan Wire) {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: n.tlsConfig(p.Fingerprint),
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConns: 1, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: false}}
	backoff := backoffFirst
	var pending []Wire
	for {
		if len(pending) == 0 {
			select {
			case <-ctx.Done():
				return
			case w := <-q:
				pending = append(pending, w)
			}
		}
	more:
		for len(pending) < maxBatch {
			select {
			case w := <-q:
				pending = append(pending, w)
			default:
				break more
			}
		}
		body, _ := json.Marshal(batch{Alerts: pending})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+p.Address+Path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				err = fmt.Errorf("answered %s", resp.Status)
			}
		}
		if err == nil {
			pending, backoff = nil, backoffFirst
			continue
		}
		n.logf("could not send %d alert(s) to %s (%s): %v; next try in %s", len(pending), p.Name, p.Address, err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

// bucket is a token bucket: ratePerMin tokens a minute.
type bucket struct {
	mu    sync.Mutex
	level float64
	last  time.Time
}

func (b *bucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.level += now.Sub(b.last).Minutes() * ratePerMin
	if b.level > ratePerMin {
		b.level = ratePerMin
	}
	b.last = now
	if b.level < 1 {
		return false
	}
	b.level--
	return true
}
