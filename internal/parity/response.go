package parity

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/response"
)

// ResponseCases is the Limbo responder's fixture (testdata/parity/response.json): alerts and Limbo events through the Go
// Responder and its real Client, against a scripted fake Limbo on a Unix socket, and what each side saw: the requests Limbo
// received and the alerts the responder passed on or raised. Within a step, calls run at once, so both lists are sorted;
// the times the queue measures are written as W.
type ResponseCases struct {
	Format string         `json:"format"`
	Cases  []ResponseCase `json:"cases"`
}

// LimboFake scripts the fake control socket.
type LimboFake struct {
	Down       bool   `json:"down,omitempty"`        // no socket at all
	Exists     string `json:"exists,omitempty"`      // GET /v1/guests/{name}: "yes", "no", "" (an older Limbo: 404 page), "odd" (200 {})
	List       string `json:"list,omitempty"`        // GET /v1/quarantine body; "" answers 500 {"error":"list failed"}
	Reply      string `json:"reply,omitempty"`       // POST /v1/quarantine body (GUEST is replaced); "" a created, applied record
	Status     int    `json:"status,omitempty"`      // POST /v1/quarantine status (0: 200)
	DelayMS    int    `json:"delay_ms,omitempty"`    // each POST /v1/quarantine waits this long first
	AdviseCode int    `json:"advise_code,omitempty"` // POST .../advisory status (0: 200)
}

// ResponseConfig sets the responder's knobs (0: its defaults).
type ResponseConfig struct {
	TimeoutMS         int `json:"timeout_ms,omitempty"`
	MaxPending        int `json:"max_pending,omitempty"`
	DelayMS           int `json:"delay_ms,omitempty"`
	BacklogThreshold  int `json:"backlog_threshold,omitempty"`
	BacklogIntervalMS int `json:"backlog_interval_ms,omitempty"`
	TickMS            int `json:"tick_ms,omitempty"`
}

// ResponseInput is one alert written to the responder or one Limbo event it observes, with an optional pause first.
type ResponseInput struct {
	Alert   string `json:"alert,omitempty"`
	Observe string `json:"observe,omitempty"`
	PauseMS int    `json:"pause_ms,omitempty"`
}

type ResponseStep struct {
	Inputs []ResponseInput `json:"inputs"`
	// Shutdown: Shutdown(grace) after the inputs instead of waiting for the queue.
	Shutdown bool `json:"shutdown,omitempty"`
	GraceMS  int  `json:"grace_ms,omitempty"`
	// golden
	Requests []string `json:"requests"`
	Out      []string `json:"out"`
}

type ResponseCase struct {
	Name   string         `json:"name"`
	Limbo  LimboFake      `json:"limbo"`
	Config ResponseConfig `json:"config"`
	Steps  []ResponseStep `json:"steps"`
}

var (
	waitRx = regexp.MustCompile(`"queue_wait":"[^"]*"|queue wait [0-9.]+[a-zµ]*s|waited [0-9.]+[a-zµ]*s|waited=[0-9.hms]+`)
	timeRx = regexp.MustCompile(`^\{"time":"[^"]*",`)
	sockRx = regexp.MustCompile(`unix [^:]*limbo\.sock`)
)

// NormaliseResponse writes what the clock decides (the queue's waits, the alert's own time) and the socket's path as fixed
// words.
func NormaliseResponse(s string) string {
	s = timeRx.ReplaceAllString(s, `{`)
	s = sockRx.ReplaceAllString(s, "unix SOCK")
	return waitRx.ReplaceAllStringFunc(s, func(m string) string {
		switch {
		case strings.HasPrefix(m, `"queue_wait"`):
			return `"queue_wait":"W"`
		case strings.HasPrefix(m, "queue wait"):
			return "queue wait W"
		case strings.HasPrefix(m, "waited="):
			return "waited=W"
		}
		return "waited W"
	})
}

type fakeLimbo struct {
	f    LimboFake
	mu   sync.Mutex
	seen []string
}

func (l *fakeLimbo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	l.mu.Lock()
	l.seen = append(l.seen, NormaliseResponse(r.Method+" "+r.URL.Path+" "+string(body)))
	l.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/guests/"):
		switch l.f.Exists {
		case "yes":
			fmt.Fprintf(w, `{"name":%q,"exists":true}`, strings.TrimPrefix(r.URL.Path, "/v1/guests/"))
		case "no":
			w.WriteHeader(404)
			fmt.Fprint(w, `{"exists":false}`)
		case "odd":
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	case r.Method == "GET" && r.URL.Path == "/v1/quarantine":
		if l.f.List == "" {
			w.WriteHeader(500)
			fmt.Fprint(w, `{"error":"list failed"}`)
			return
		}
		fmt.Fprint(w, l.f.List)
	case r.Method == "POST" && r.URL.Path == "/v1/quarantine":
		var in struct{ Guest string }
		_ = json.Unmarshal(body, &in)
		time.Sleep(time.Duration(l.f.DelayMS) * time.Millisecond)
		if l.f.Status != 0 {
			w.WriteHeader(l.f.Status)
		}
		reply := l.f.Reply
		if reply == "" {
			reply = `{"record":{"id":"q-GUEST","guest":"GUEST","level":"restrict"},"created":true,"applied":true}`
		}
		fmt.Fprint(w, strings.ReplaceAll(reply, "GUEST", in.Guest))
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/advisory"):
		if l.f.AdviseCode != 0 {
			w.WriteHeader(l.f.AdviseCode)
		}
		fmt.Fprint(w, `{}`)
	default:
		http.NotFound(w, r)
	}
}

type lines struct {
	mu  sync.Mutex
	out []string
}

func (s *lines) Write(a alert.Alert) error {
	b, err := json.Marshal(a)
	s.mu.Lock()
	s.out = append(s.out, NormaliseResponse(string(b)))
	s.mu.Unlock()
	return err
}

func (s *lines) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.out
	s.out = nil
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// RunResponse runs one case through the Go responder.
func RunResponse(c ResponseCase, dir string) (ResponseCase, error) {
	sock := filepath.Join(dir, "limbo.sock")
	fake := &fakeLimbo{f: c.Limbo}
	if !c.Limbo.Down {
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return c, err
		}
		srv := &http.Server{Handler: fake}
		go func() { _ = srv.Serve(ln) }()
		defer srv.Close()
	}
	out := &lines{}
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	r := &response.Responder{Next: out, Limbo: response.NewClient(sock), QuarantineTimeout: ms(c.Config.TimeoutMS),
		MaxPending: c.Config.MaxPending, DelayThreshold: ms(c.Config.DelayMS), BacklogThreshold: c.Config.BacklogThreshold,
		BacklogInterval: ms(c.Config.BacklogIntervalMS), MonitorTick: ms(c.Config.TickMS)}
	for i := range c.Steps {
		st := &c.Steps[i]
		for _, in := range st.Inputs {
			time.Sleep(ms(in.PauseMS))
			if in.Alert != "" {
				var a alert.Alert
				if err := json.Unmarshal([]byte(in.Alert), &a); err != nil {
					return c, err
				}
				_ = r.Write(a)
			}
			if in.Observe != "" {
				var e detect.Event
				if err := json.Unmarshal([]byte(in.Observe), &e); err != nil {
					return c, err
				}
				r.Observe(e)
			}
		}
		if st.Shutdown {
			r.Shutdown(ms(st.GraceMS))
		} else {
			r.Wait()
		}
		fake.mu.Lock()
		st.Requests = fake.seen
		fake.seen = nil
		fake.mu.Unlock()
		sort.Strings(st.Requests)
		if st.Requests == nil {
			st.Requests = []string{}
		}
		st.Out = out.take()
	}
	return c, nil
}

func limboAlert(detector, sev, kind, guest string, extra map[string]string) string {
	f := map[string]string{"guest": guest}
	for k, v := range extra {
		f[k] = v
	}
	a := alert.FromFinding(detect.Finding{DetectorID: detector, Severity: detect.Severity(sev), Summary: detector + " on " + guest + " <&>",
		Event: detect.Event{Source: "limbo", Kind: kind, Time: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), Fields: f}})
	a.Time = time.Date(2026, 11, 5, 12, 0, 1, 0, time.UTC)
	return line(a)
}

func limboEvent(kind, guest string) string {
	b, _ := json.Marshal(detect.Event{Source: "limbo", Kind: kind, Time: time.Date(2026, 11, 5, 12, 0, 2, 0, time.UTC), Fields: map[string]string{"guest": guest}})
	return string(b)
}

// AllResponse computes the fixture with the Go responder (the cases of internal/response's tests, and more).
func AllResponse(tmp func() string) (ResponseCases, error) {
	f := ResponseCases{Format: "heimdall-parity-response/1"}
	crit := func(kind, guest string) ResponseInput {
		return ResponseInput{Alert: limboAlert("limbo-guest", "critical", kind, guest, nil)}
	}
	net := func(reason, sev, guest string) ResponseInput {
		return ResponseInput{Alert: limboAlert("limbo-network", sev, "net.anomaly", guest, map[string]string{"reason": reason})}
	}
	obs := func(kind, guest string) ResponseInput { return ResponseInput{Observe: limboEvent(kind, guest)} }
	one := func(name string, l LimboFake, cfg ResponseConfig, steps ...ResponseStep) {
		f.Cases = append(f.Cases, ResponseCase{Name: name, Limbo: l, Config: cfg, Steps: steps})
	}
	step := func(in ...ResponseInput) ResponseStep { return ResponseStep{Inputs: in} }
	exists := LimboFake{Exists: "yes", List: "[]"}
	// which alerts trigger (responder_test.go TestTriggers and the network and exchange tests)
	one("triggers and non-triggers", exists, ResponseConfig{}, step(
		crit("guest.start", "web1"), crit("policy.remove", "db-2"), crit("image.rejected", "img"),
		ResponseInput{Alert: limboAlert("limbo-guest", "warning", "guest.start", "warn1", nil)},
		crit("guest.start", "Bad_Name"), crit("guest.start", "toolongguestname"), crit("guest.start", ""),
		net("host_probe", "critical", "n1"), net("lan_probe", "critical", "n2"), net("scan", "warning", "n3"),
		net("ipv6", "warning", "n4"), net("scan", "info", "n5"), net("", "critical", "n6"),
		ResponseInput{Alert: limboAlert("limbo-exchange", "warning", "exchange.held", "x1", map[string]string{"sha256": "ab"})},
		ResponseInput{Alert: limboAlert("limbo-exchange", "info", "exchange.fail", "x2", nil)},
		ResponseInput{Alert: limboAlert("injection-phrase", "critical", "guest.start", "inj", nil)}))
	one("a hold that was not enforced", LimboFake{Exists: "yes", List: "[]", Reply: `{"record":{"id":"q1","guest":"GUEST","level":"restrict"},"created":true,"applied":false,"error":"nft failed"}`}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("a repeat: not created, no explanation", LimboFake{Exists: "yes", List: "[]", Reply: `{"record":{"id":"q1","guest":"GUEST","level":"restrict"},"created":false,"applied":true}`}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("Limbo refuses", LimboFake{Exists: "yes", List: "[]", Status: 409, Reply: `{"error":"guest is not running"}`}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("Limbo refuses without a reason", LimboFake{Exists: "yes", List: "[]", Status: 500, Reply: `oops`}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("a reply that is not JSON", LimboFake{Exists: "yes", List: "[]", Reply: `not json`}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("Limbo is down", LimboFake{Down: true}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("Limbo hangs", LimboFake{Exists: "yes", List: "[]", DelayMS: 600}, ResponseConfig{TimeoutMS: 150}, step(crit("guest.start", "web1")))
	one("the advisory route fails", LimboFake{Exists: "yes", List: "[]", AdviseCode: 500}, ResponseConfig{}, step(crit("guest.start", "web1")))
	// the re-check (queue_test.go): torn down, older Limbo, odd answers, holds
	one("the guest no longer exists", LimboFake{Exists: "no", List: "[]"}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("an older Limbo: no guests route", LimboFake{List: "[]"}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("an odd guests answer", LimboFake{Exists: "odd", List: "[]"}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("the list fails", LimboFake{Exists: "yes"}, ResponseConfig{}, step(crit("guest.start", "web1")))
	hold := func(level, status, opened string) string {
		return fmt.Sprintf(`[{"guest":"web1","level":%q,"status":%q,"opened":%q},{"guest":"other","level":"isolate","status":"open","opened":"2026-11-05T13:00:00Z"}]`, level, status, opened)
	}
	one("held at isolate", LimboFake{Exists: "yes", List: hold("isolate", "open", "2026-11-05T11:00:00Z")}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("held at restrict since after the trigger", LimboFake{Exists: "yes", List: hold("restrict", "open", "2026-11-05T12:00:01Z")}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("held at restrict since before the trigger", LimboFake{Exists: "yes", List: hold("restrict", "dangerous", "2026-11-05T11:59:59Z")}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("a released hold does not count", LimboFake{Exists: "yes", List: hold("isolate", "released", "2026-11-05T13:00:00Z")}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("an unknown level does not count", LimboFake{Exists: "yes", List: hold("quarantine", "open", "2026-11-05T13:00:00Z")}, ResponseConfig{}, step(crit("guest.start", "web1")))
	one("a list that is not JSON", LimboFake{Exists: "yes", List: "[{"}, ResponseConfig{}, step(crit("guest.start", "web1")))
	// the queue: eight at once, the rest wait in order; merges; marks from later Limbo events
	slow := LimboFake{Exists: "yes", List: "[]", DelayMS: 400}
	var nine []ResponseInput
	for i := 0; i < 8; i++ {
		nine = append(nine, crit("guest.start", fmt.Sprintf("busy%d", i)))
	}
	one("merged while waiting; priority raised", slow, ResponseConfig{}, step(append(nine,
		net("scan", "warning", "late1"), ResponseInput{Alert: limboAlert("limbo-guest", "critical", "policy.remove", "late1", nil)},
		net("scan", "warning", "late1"), crit("guest.start", "late2"))...))
	one("stopped while waiting: skipped", slow, ResponseConfig{}, step(append(nine, crit("guest.start", "late1"), obs("guest.stop", "late1"))...))
	one("policy applied again while waiting: skipped", slow, ResponseConfig{}, step(append(nine, crit("policy.remove", "late1"), obs("policy.apply", "late1"))...))
	one("stopped, then started again: sent", slow, ResponseConfig{}, step(append(nine, crit("guest.start", "late1"), obs("guest.stop", "late1"), obs("guest.start", "late1"))...))
	one("a network anomaly is not cleared by a stop", slow, ResponseConfig{}, step(append(nine, net("lan_probe", "critical", "late1"), obs("guest.stop", "late1"))...))
	one("an event before the trigger does not clear it", slow, ResponseConfig{}, step(append(nine, obs("guest.stop", "late1"), crit("guest.start", "late1"))...))
	one("observed events of other sources and bad names are ignored", slow, ResponseConfig{}, step(append(nine,
		crit("guest.start", "late1"), ResponseInput{Observe: `{"source":"agent","kind":"guest.stop","fields":{"guest":"late1"}}`},
		obs("guest.stop", "Late1"))...))
	one("in flight: a repeat is coalesced", slow, ResponseConfig{}, step(crit("guest.start", "web1"), ResponseInput{Alert: limboAlert("limbo-guest", "critical", "policy.remove", "web1", nil), PauseMS: 100}))
	one("over the cap: refused loudly", slow, ResponseConfig{MaxPending: 2}, step(append(nine, crit("guest.start", "w1"), crit("guest.start", "w2"), crit("guest.start", "w3"))...))
	one("late and backlog alerts", LimboFake{Exists: "yes", List: "[]", DelayMS: 500}, ResponseConfig{DelayMS: 150, BacklogThreshold: 1, BacklogIntervalMS: 60000, TickMS: 50},
		step(append(nine, crit("guest.start", "w1"), net("scan", "warning", "w2"))...))
	one("shutdown with requests waiting", LimboFake{Exists: "yes", List: "[]", DelayMS: 300}, ResponseConfig{},
		ResponseStep{Inputs: append(nine, crit("guest.start", "w1"), net("scan", "warning", "w2")), Shutdown: true, GraceMS: 50},
		step(crit("guest.start", "after")))
	one("two steps: a later trigger is its own request", exists, ResponseConfig{}, step(crit("guest.start", "web1")), step(crit("policy.remove", "web1")))
	for i := range f.Cases {
		var err error
		if f.Cases[i], err = RunResponse(f.Cases[i], tmp()); err != nil {
			return f, err
		}
	}
	return f, nil
}
