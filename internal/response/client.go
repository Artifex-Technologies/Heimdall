// Package response is Heimdall's active half: when a detector finds that a Limbo
// guest is running outside its safety rules, cut it off, then ask Sarina for an
// opinion for the human who has to decide.
//
// The constraint that shapes this package is deliberate and enforced by Limbo,
// not by Heimdall's good behaviour: Heimdall reaches Limbo only through its control
// socket, which can restrict a guest and attach an advisory and nothing else.
// There is no call here that releases a guest or marks one safe, because no such
// route exists on that socket. A compromised Heimdall can therefore make a guest
// more restricted, never less. See Limbo's docs/QUARANTINE.md.
package response

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Record is the subset of Limbo's quarantine record Heimdall needs.
type Record struct {
	ID    string `json:"id"`
	Guest string `json:"guest"`
	Level string `json:"level"`
}

// Result is Limbo's reply to a quarantine request.
type Result struct {
	Record  Record `json:"record"`
	Created bool   `json:"created"`
	// Applied reports whether the hold was actually enforced on the running
	// guest. False with a record means the hold is recorded but not (yet) in
	// force, which a caller must treat as unresolved, not as success.
	Applied bool   `json:"applied"`
	Error   string `json:"error"`
}

// Client talks to Limbo's control socket.
type Client struct {
	base string
	http *http.Client
}

// NewClient connects to a unix socket path.
func NewClient(socket string) *Client {
	return &Client{
		base: "http://limbo",
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			}},
		},
	}
}

// NewClientHTTP is for tests: any base URL and HTTP client.
func NewClientHTTP(base string, h *http.Client) *Client { return &Client{base: base, http: h} }

// Quarantine asks Limbo to hold a guest at the restrict level. Repeating the
// request is safe and re-asserts the hold.
func (c *Client) Quarantine(ctx context.Context, guest, reason, source string, evidence map[string]string) (Result, error) {
	var res Result
	err := c.do(ctx, "POST", "/v1/quarantine", map[string]any{
		"guest": guest, "reason": reason, "source": source, "level": "restrict", "evidence": evidence,
	}, &res)
	return res, err
}

// Advise attaches an opinion to a quarantine record. It cannot change the
// record's status; only a human verdict can.
func (c *Client) Advise(ctx context.Context, id, source, text string) error {
	return c.do(ctx, "POST", "/v1/quarantine/"+id+"/advisory", map[string]string{"source": source, "text": text}, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("limbo control socket: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("limbo: %s", e.Error)
		}
		return fmt.Errorf("limbo: %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// QuarantineStatus is a read-only look at what Limbo holds for a guest, from the
// control socket's list route (which Limbo allows Heimdall; it changes nothing).
// "Holding" mirrors Limbo's own rule: a record that is open or dangerous. It
// returns the strongest level among them and the newest open time at that level.
func (c *Client) QuarantineStatus(ctx context.Context, guest string) (level string, opened time.Time, found bool, err error) {
	var recs []struct {
		Guest  string    `json:"guest"`
		Level  string    `json:"level"`
		Status string    `json:"status"`
		Opened time.Time `json:"opened"`
	}
	if err = c.do(ctx, "GET", "/v1/quarantine", nil, &recs); err != nil {
		return "", time.Time{}, false, err
	}
	rank := map[string]int{"restrict": 1, "isolate": 2}
	for _, r := range recs {
		if r.Guest != guest || (r.Status != "open" && r.Status != "dangerous") || rank[r.Level] == 0 {
			continue
		}
		if !found || rank[r.Level] > rank[level] || (r.Level == level && r.Opened.After(opened)) {
			level, opened, found = r.Level, r.Opened, true
		}
	}
	return level, opened, found, nil
}
