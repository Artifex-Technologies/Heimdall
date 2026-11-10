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
	// what the fake Sarina was asked (sorted; absent without one)
	Sarina []string `json:"sarina,omitempty"`
}

// SarinaFake scripts a fake sarina-service on loopback TCP (nil: no advisor, as with sarina_url unset).
type SarinaFake struct {
	Down         bool   `json:"down,omitempty"`          // nothing listens: connection refused
	NotInstalled bool   `json:"not_installed,omitempty"` // IfInstalled says no: nothing is asked
	Token        string `json:"token,omitempty"`
	CreateStatus int    `json:"create_status,omitempty"` // POST /v1/sessions (0: 200)
	Create       string `json:"create,omitempty"`        // its body; "": {"session_id":"s-1","tools":0}
	ChatStatus   int    `json:"chat_status,omitempty"`
	Chat         string `json:"chat,omitempty"` // "": a SUSPICIOUS opinion
	ChatDelayMS  int    `json:"chat_delay_ms,omitempty"`
	Drop         int    `json:"drop,omitempty"`       // the first N POST /v1/sessions lose their connection without a reply
	TimeoutMS    int    `json:"timeout_ms,omitempty"` // the client's HTTP timeout (0: its default)
}

// SarinaRetryMS is the wait before the advisor's one retry in the fixture (both languages set it).
const SarinaRetryMS = 20

type ResponseCase struct {
	Name   string         `json:"name"`
	Limbo  LimboFake      `json:"limbo"`
	Sarina *SarinaFake    `json:"sarina,omitempty"`
	Config ResponseConfig `json:"config"`
	Steps  []ResponseStep `json:"steps"`
}

var (
	waitRx = regexp.MustCompile(`"queue_wait":"[^"]*"|queue wait [0-9.]+[a-zµ]*s|waited [0-9.]+[a-zµ]*s|waited=[0-9.hms]+`)
	timeRx = regexp.MustCompile(`^\{"time":"[^"]*",`)
	sockRx = regexp.MustCompile(`unix [^:]*limbo\.sock`)
	portRx = regexp.MustCompile(`127\.0\.0\.1:[0-9]+`)
	atRx   = regexp.MustCompile(`raised at [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z`)
)

// NormaliseResponse writes what the clock decides (the queue's waits, the alert's own time) and the socket's path as fixed
// words.
func NormaliseResponse(s string) string {
	s = timeRx.ReplaceAllString(s, `{`)
	s = sockRx.ReplaceAllString(s, "unix SOCK")
	s = portRx.ReplaceAllString(s, "127.0.0.1:PORT")
	s = atRx.ReplaceAllString(s, "raised at T")
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

type fakeSarina struct {
	f     SarinaFake
	mu    sync.Mutex
	seen  []string
	drops int
}

func (f *fakeSarina) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, NormaliseResponse(r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization")+" "+string(body)))
	drop := r.Method == "POST" && r.URL.Path == "/v1/sessions" && f.drops < f.f.Drop
	if drop {
		f.drops++
	}
	f.mu.Unlock()
	if drop {
		panic(http.ErrAbortHandler) // the connection is closed without a reply
	}
	w.Header().Set("Content-Type", "application/json")
	reply := func(code int, body, def string) {
		if code != 0 {
			w.WriteHeader(code)
		}
		if body == "" {
			body = def
		}
		fmt.Fprint(w, body)
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/sessions":
		reply(f.f.CreateStatus, f.f.Create, `{"session_id":"s-1","tools":0}`)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/chat"):
		time.Sleep(time.Duration(f.f.ChatDelayMS) * time.Millisecond)
		reply(f.f.ChatStatus, f.f.Chat, `{"final_output":"SUSPICIOUS: a guest started without its firewall policy <&>.","stop_reason":"completed"}`)
	case r.Method == "DELETE":
		fmt.Fprint(w, `{"evicted":true}`)
	default:
		w.WriteHeader(404)
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
	var sar *fakeSarina
	if c.Sarina != nil {
		sar = &fakeSarina{f: *c.Sarina}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return c, err
		}
		url := "http://" + ln.Addr().String()
		if c.Sarina.Down {
			ln.Close()
		} else {
			srv := &http.Server{Handler: sar}
			go func() { _ = srv.Serve(ln) }()
			defer srv.Close()
		}
		adv, err := response.NewSarina(url, c.Sarina.Token, "/var/lib/heimdall")
		if err != nil {
			return c, err
		}
		timeout := 150 * time.Second
		if c.Sarina.TimeoutMS > 0 {
			timeout = ms(c.Sarina.TimeoutMS)
		}
		adv.SetTestHooks(timeout, ms(SarinaRetryMS))
		installed := !c.Sarina.NotInstalled
		r.Advisor = response.IfInstalled{Inner: adv, Installed: func() bool { return installed }}
	}
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
		if sar != nil {
			sar.mu.Lock()
			st.Sarina = sar.seen
			sar.seen = nil
			sar.mu.Unlock()
			sort.Strings(st.Sarina)
			if st.Sarina == nil {
				st.Sarina = []string{}
			}
		}
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

// addSarinaCases adds the Sarina advisory's cases (internal/response's failure_test.go and response_test.go, and more): a
// scripted sarina-service on loopback TCP beside the fake Limbo.
func addSarinaCases(f *ResponseCases, crit func(kind, guest string) ResponseInput, net func(reason, sev, guest string) ResponseInput, step func(in ...ResponseInput) ResponseStep) {
	exists := LimboFake{Exists: "yes", List: "[]"}
	one := func(name string, l LimboFake, s SarinaFake, cfg ResponseConfig, steps ...ResponseStep) {
		f.Cases = append(f.Cases, ResponseCase{Name: "sarina: " + name, Limbo: l, Sarina: &s, Config: cfg, Steps: steps})
	}
	web := step(crit("guest.start", "web1"))
	one("an opinion attached to a new hold", exists, SarinaFake{}, ResponseConfig{}, web, step(net("lan_probe", "critical", "n1")))
	one("with a token", exists, SarinaFake{Token: "tok-123"}, ResponseConfig{}, web)
	one("not installed: nothing asked", exists, SarinaFake{NotInstalled: true}, ResponseConfig{}, web)
	one("a repeat hold: not asked", LimboFake{Exists: "yes", List: "[]", Reply: `{"record":{"id":"q1","guest":"GUEST","level":"restrict"},"created":false,"applied":true}`}, SarinaFake{}, ResponseConfig{}, web)
	one("a hold Limbo refused: not asked", LimboFake{Exists: "yes", List: "[]", Status: 409, Reply: `{"error":"no"}`}, SarinaFake{}, ResponseConfig{}, web)
	one("the advisory route fails", LimboFake{Exists: "yes", List: "[]", AdviseCode: 500}, SarinaFake{}, ResponseConfig{}, web)
	fails := []struct {
		name string
		s    SarinaFake
	}{
		{"auth 401 on create", SarinaFake{CreateStatus: 401, Create: `{"detail":"bad token"}`}},
		{"auth 403 on create", SarinaFake{CreateStatus: 403, Create: " "}},
		{"server error on create", SarinaFake{CreateStatus: 500, Create: `{"detail":"boom"}`}},
		{"server error with a detail that is not text", SarinaFake{CreateStatus: 503, Create: `{"detail":{"why":["a",1.5,true,null],"n":1e21,"m":{}}}`}},
		{"server error with a numeric detail", SarinaFake{CreateStatus: 500, Create: `{"detail":12}`}},
		{"server error with a null detail", SarinaFake{CreateStatus: 500, Create: `{"detail":null}`}},
		{"server error with a detail list", SarinaFake{CreateStatus: 500, Create: `{"detail":[{"loc":["body","cwd"],"msg":"field required"}]}`}},
		{"a long detail is cut", SarinaFake{CreateStatus: 500, Create: `{"detail":"` + strings.Repeat("x", 300) + `"}`}},
		{"create rejected (cwd missing)", SarinaFake{CreateStatus: 400, Create: `{"detail":"cwd does not exist"}`}},
		{"create 404", SarinaFake{CreateStatus: 404, Create: `{"detail":"no route"}`}},
		{"create reply not JSON", SarinaFake{Create: `<html>nginx</html>`}},
		{"create reply truncated", SarinaFake{Create: `{"session_id":"s-1","to`}},
		{"create reply without session_id", SarinaFake{Create: `{"tools":0}`}},
		{"session_id that is not a path segment", SarinaFake{Create: `{"session_id":"../x","tools":0}`}},
		{"session_id of the wrong type", SarinaFake{Create: `{"session_id":5,"tools":0}`}},
		{"tools not reported", SarinaFake{Create: `{"session_id":"s-1"}`}},
		{"tools null", SarinaFake{Create: `{"session_id":"s-1","tools":null}`}},
		{"tools nonzero", SarinaFake{Create: `{"session_id":"s-1","tools":70}`}},
		{"tools not a whole number", SarinaFake{Create: `{"session_id":"s-1","tools":0.5}`}},
		{"tools as text", SarinaFake{Create: `{"session_id":"s-1","tools":"0"}`}},
		{"keys in another case", SarinaFake{Create: `{"Session_ID":"s-2","TOOLS":0}`}},
		{"evicted mid-conversation", SarinaFake{ChatStatus: 404, Chat: `{"detail":"session not found"}`}},
		{"auth revoked on chat", SarinaFake{ChatStatus: 401, Chat: " "}},
		{"server error on chat", SarinaFake{ChatStatus: 500, Chat: `{"detail":"run failed"}`}},
		{"chat reply truncated", SarinaFake{Chat: `{"final_output":"SUSP`}},
		{"chat reply empty", SarinaFake{Chat: `{"final_output":"  ","stop_reason":"completed"}`}},
		{"chat reply without an opinion", SarinaFake{Chat: `{"stop_reason":"completed"}`}},
		{"chat reply over the size limit", SarinaFake{Chat: `{"final_output":"` + strings.Repeat("A", 1<<20) + `"}`}},
		{"model backend error reported as 200", SarinaFake{Chat: `{"final_output":"connection refused to model","stop_reason":"backend_error"}`}},
		{"a huge opinion is cut on a letter", SarinaFake{Chat: `{"final_output":"` + strings.Repeat("é", 100000) + `"}`}},
		{"an opinion with escapes", SarinaFake{Chat: `{"final_output":"BENIGN \ud800   <b> \"ok\"","stop_reason":"completed"}`}},
		{"Sarina is down", SarinaFake{Down: true}},
		{"a dropped connection is retried once", SarinaFake{Drop: 1}},
		{"dropped twice: unreachable", SarinaFake{Drop: 2}},
		{"a slow model times out, the chat is not repeated", SarinaFake{ChatDelayMS: 400, TimeoutMS: 150}},
	}
	for _, c := range fails {
		one(c.name, exists, c.s, ResponseConfig{}, web)
	}
	// at most 2 advisories at once: the third new hold while two are running is recorded as sarina_busy
	three := step(crit("guest.start", "a1"), ResponseInput{Alert: limboAlert("limbo-guest", "critical", "guest.start", "a2", nil), PauseMS: 150},
		ResponseInput{Alert: limboAlert("limbo-guest", "critical", "guest.start", "a3", nil), PauseMS: 150})
	one("busy: a third advisory is skipped", exists, SarinaFake{ChatDelayMS: 900}, ResponseConfig{}, three)
	// the backlog note: one tool-less consultation about the queue, an untrusted note that changes nothing
	repeat := LimboFake{Exists: "yes", List: "[]", DelayMS: 500, Reply: `{"record":{"id":"q-GUEST","guest":"GUEST","level":"restrict"},"created":false,"applied":true}`}
	var nine []ResponseInput
	for i := 0; i < 8; i++ {
		nine = append(nine, crit("guest.start", fmt.Sprintf("busy%d", i)))
	}
	backlog := step(append(nine, crit("guest.start", "w1"), net("scan", "warning", "w2"))...)
	cfg := ResponseConfig{BacklogThreshold: 1, BacklogIntervalMS: 60000, TickMS: 50}
	one("a backlog note", repeat, SarinaFake{Chat: `{"final_output":"Limbo is slow.\tCheck it\u0007 first.\nThen w1.\u007f é","stop_reason":"completed"}`}, cfg, backlog)
	one("a backlog note that is only control characters", repeat, SarinaFake{Chat: `{"final_output":"\u0001\u0002","stop_reason":"completed"}`}, cfg, backlog)
	one("a backlog note that fails", repeat, SarinaFake{CreateStatus: 500, Create: `{"detail":"down"}`}, cfg, backlog)
	one("a backlog note: not installed", repeat, SarinaFake{NotInstalled: true}, cfg, backlog)
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
	addSarinaCases(&f, crit, net, step)
	for i := range f.Cases {
		var err error
		if f.Cases[i], err = RunResponse(f.Cases[i], tmp()); err != nil {
			return f, err
		}
	}
	return f, nil
}
