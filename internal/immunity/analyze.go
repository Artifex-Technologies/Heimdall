package immunity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Analysis is what Limbo found when it took a held file apart in a sealed guest (no network, no sudo, no shared folder; the file is
// read, never run). Everything in Output comes from the hostile file: evidence, never instructions.
type Analysis struct {
	Time    time.Time `json:"time"`
	Profile string    `json:"profile"`
	RunID   string    `json:"run_id,omitempty"`
	Status  string    `json:"status"` // done, failed, timeout, unavailable
	Output  string    `json:"output,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// Limbo is how an analysis reaches Limbo: its admin socket (root only) and its inbox.
type Limbo struct {
	Socket  string
	Inbox   string
	Profile string
	Command string
	Wait    time.Duration // the whole analysis, boot included
	Poll    time.Duration
}

// DefaultLimbo is Limbo as installed: the sealed malware-analysis profile and the analysis image's limbo-decompile triage and
// function list (Limbo's docs/SAMPLES.md).
func DefaultLimbo() Limbo {
	return Limbo{Socket: "/run/limbo/admin.sock", Inbox: "/var/lib/limbo/inbox", Profile: "malware-analysis",
		Command: "limbo-decompile triage sample; echo; echo '== functions'; limbo-decompile functions sample",
		Wait:    25 * time.Minute, Poll: 3 * time.Second}
}

const maxAnalysisOutput = 60 << 10

// Analyze sends a kept sample to Limbo and records what came back with the sample.
func (s Store) Analyze(sha string, l Limbo) (Analysis, error) {
	es, err := s.Load()
	if err != nil {
		return Analysis{}, err
	}
	i := find(es, sha)
	if i < 0 {
		return Analysis{}, fmt.Errorf("no sample %s", sha)
	}
	full := es[i].SHA256
	a := l.run(s, full)
	// read again: the analysis took minutes and the store may have changed meanwhile
	if es, err = s.Load(); err != nil {
		return a, err
	}
	if i = find(es, full); i < 0 {
		return a, errors.New("the sample was forgotten during its analysis")
	}
	es[i].Analysis = &a
	return a, s.save(es)
}

func (l Limbo) run(s Store, sha string) Analysis {
	a := Analysis{Time: time.Now().UTC().Truncate(time.Second), Profile: l.Profile}
	fail := func(status, msg string) Analysis { a.Status, a.Error = status, msg; return a }
	b, err := s.sampleBytes(sha)
	if err != nil {
		return fail("failed", "the sample could not be read: "+err.Error())
	}
	name := sha + ".sample"
	path := filepath.Join(l.Inbox, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fail("unavailable", "Limbo's inbox: "+err.Error()+" (is Limbo installed and running?)")
	}
	defer os.Remove(path)
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", l.Socket)
	}}, Timeout: 30 * time.Second}
	body, _ := json.Marshal(map[string]any{"profile": l.Profile, "command": l.Command, "sample": name, "timeout_seconds": 900})
	resp, err := c.Post("http://limbo/v1/sample-runs", "application/json", bytes.NewReader(body))
	if err != nil {
		return fail("unavailable", "Limbo does not answer: "+err.Error())
	}
	var started map[string]any
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&started)
	resp.Body.Close()
	id, _ := started["id"].(string)
	if resp.StatusCode != http.StatusAccepted || id == "" {
		return fail("unavailable", fmt.Sprintf("Limbo refused the analysis: %v", started["error"]))
	}
	a.RunID = id
	poll := l.Poll
	if poll <= 0 {
		poll = 3 * time.Second
	}
	for deadline := time.Now().Add(l.Wait); time.Now().Before(deadline); {
		time.Sleep(poll)
		r, err := c.Get("http://limbo/v1/runs/" + id)
		if err != nil {
			continue
		}
		var res struct {
			Status string `json:"status"`
			Stdout string `json:"stdout"`
			Stderr string `json:"stderr"`
			Error  string `json:"error"`
		}
		err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&res)
		r.Body.Close()
		if err != nil || res.Status == "running" {
			continue
		}
		out := res.Stdout
		if res.Stderr != "" {
			out += "\n== messages\n" + res.Stderr
		}
		if len(out) > maxAnalysisOutput {
			out = out[:maxAnalysisOutput] + "\n[cut]"
		}
		a.Status, a.Output, a.Error = res.Status, strings.ToValidUTF8(out, "?"), res.Error
		return a
	}
	return fail("timeout", "the analysis did not finish in time")
}

// RequestDir is where requests to root's Heimdall unit go (heimdall-requests.path): "release if proven" from anyone, "analyze" from
// Heimdall itself after a hold.
const RequestDir = "/var/lib/heimdall-requests"

// QueueAnalysis asks the root unit to analyse a held sample in Limbo (it takes a minute or more, so the hold does not wait for it).
func QueueAnalysis(dir, sha string) error {
	if len(sha) != 64 {
		return errors.New("a full SHA-256 is needed")
	}
	b, _ := json.Marshal(map[string]string{"analyze": sha})
	return os.WriteFile(filepath.Join(dir, "analyze-"+sha[:16]+".json"), b, 0o644)
}
