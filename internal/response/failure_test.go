package response

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// svc is a scriptable fake sarina-service: each stage can be overridden, and
// every request is recorded so tests can assert cleanup and what was (not) sent.
type svc struct {
	mu     sync.Mutex
	calls  []string
	create func(w http.ResponseWriter)
	chat   func(w http.ResponseWriter)
}

func (f *svc) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/sessions":
			if f.create != nil {
				f.create(w)
				return
			}
			w.Write([]byte(`{"session_id":"s-1","tools":0}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/chat"):
			if f.chat != nil {
				f.chat(w)
				return
			}
			w.Write([]byte(`{"final_output":"BENIGN","stop_reason":"completed"}`))
		case r.Method == "DELETE":
			w.Write([]byte(`{"evicted":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *svc) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "; ")
}

func status(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code); w.Write([]byte(body)) }
}

func advise(t *testing.T, f *svc) (string, error, *Sarina) {
	t.Helper()
	srv := f.server(t)
	s, err := NewSarina(srv.URL, "", "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	s.retryDelay = time.Millisecond
	out, err := s.Advise(context.Background(), limboAlert("guest.start", "lab", detect.SeverityCritical))
	return out, err, s
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	got, msg, remedy := ErrorInfo(err)
	if got != code || msg == "" || remedy == "" {
		t.Fatalf("code=%q msg=%q remedy=%q err=%v, want code %q with a message and remedy", got, msg, remedy, err, code)
	}
}

func TestSarinaFailureCodes(t *testing.T) {
	cases := []struct {
		name        string
		f           *svc
		code        string
		wantChat    bool // evidence reached the service
		wantDeleted bool // the session was closed afterwards
	}{
		{"auth 401 on create", &svc{create: status(401, `{"detail":"bad token"}`)}, CodeAuth, false, false},
		{"auth 403 on create", &svc{create: status(403, ``)}, CodeAuth, false, false},
		{"server error on create", &svc{create: status(500, `{"detail":"boom"}`)}, CodeServerError, false, false},
		{"create rejected (cwd missing)", &svc{create: status(400, `{"detail":"cwd does not exist"}`)}, CodeBadResponse, false, false},
		{"create reply not JSON", &svc{create: status(200, `<html>nginx</html>`)}, CodeBadResponse, false, false},
		{"create reply truncated", &svc{create: status(200, `{"session_id":"s-1","to`)}, CodeBadResponse, false, false},
		{"create reply without session_id", &svc{create: status(200, `{"tools":0}`)}, CodeBadResponse, false, false},
		{"session_id that is not a path segment", &svc{create: status(200, `{"session_id":"../x","tools":0}`)}, CodeBadResponse, false, false},
		{"tools not reported", &svc{create: status(200, `{"session_id":"s-1"}`)}, CodeToolsNonzero, false, true},
		{"tools nonzero", &svc{create: status(200, `{"session_id":"s-1","tools":70}`)}, CodeToolsNonzero, false, true},
		{"evicted mid-conversation", &svc{chat: status(404, `{"detail":"session not found"}`)}, CodeEvicted, true, true},
		{"auth revoked on chat", &svc{chat: status(401, ``)}, CodeAuth, true, true},
		{"server error on chat", &svc{chat: status(500, `{"detail":"run failed"}`)}, CodeServerError, true, true},
		{"chat reply truncated", &svc{chat: status(200, `{"final_output":"SUSP`)}, CodeBadResponse, true, true},
		{"chat reply empty", &svc{chat: status(200, `{"final_output":"  ","stop_reason":"completed"}`)}, CodeBadResponse, true, true},
		{"chat reply over the size limit", &svc{chat: status(200, `{"final_output":"`+strings.Repeat("A", maxReply)+`"}`)}, CodeBadResponse, true, true},
		{"model backend error reported as 200", &svc{chat: status(200, `{"final_output":"connection refused to model","stop_reason":"backend_error"}`)}, CodeBackendError, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err, _ := advise(t, c.f)
			if out != "" {
				t.Fatalf("a failed consultation must not return advice: %q", out)
			}
			wantCode(t, err, c.code)
			all := c.f.all()
			if got := strings.Contains(all, "/chat"); got != c.wantChat {
				t.Errorf("chat sent=%v want %v: %s", got, c.wantChat, all)
			}
			if got := strings.Contains(all, "DELETE /v1/sessions/s-1"); got != c.wantDeleted {
				t.Errorf("deleted=%v want %v: %s", got, c.wantDeleted, all)
			}
		})
	}
}

func TestSarinaServerErrorQuotesTheServicesReason(t *testing.T) {
	_, err, _ := advise(t, &svc{create: status(400, `{"detail":"cwd does not exist"}`)})
	if !strings.Contains(err.Error(), "cwd does not exist") {
		t.Fatalf("the service's own reason is the diagnosis and must be kept: %v", err)
	}
}

func TestSarinaUnreachableRetriesOnceThenReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens any more: connection refused
	s, _ := NewSarina(url, "", "/tmp")
	s.retryDelay = time.Millisecond
	start := time.Now()
	_, err := s.Advise(context.Background(), limboAlert("guest.start", "lab", detect.SeverityCritical))
	wantCode(t, err, CodeUnreachable)
	if !strings.Contains(err.Error(), "/healthz") {
		t.Errorf("remedy should say how to check: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("must give up quickly, not hang")
	}
}

func TestSarinaRetriesADroppedConnectionOnce(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/sessions" && n.Add(1) == 1 {
			panic(http.ErrAbortHandler) // Sarina restarting: connection dropped mid-request
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/sessions":
			w.Write([]byte(`{"session_id":"s-1","tools":0}`))
		case r.Method == "POST":
			w.Write([]byte(`{"final_output":"BENIGN"}`))
		}
	}))
	defer srv.Close()
	s, _ := NewSarina(srv.URL, "", "/tmp")
	s.retryDelay = time.Millisecond
	out, err := s.Advise(context.Background(), limboAlert("guest.start", "lab", detect.SeverityCritical))
	if err != nil || out != "BENIGN" || n.Load() != 2 {
		t.Fatalf("out=%q err=%v creates=%d", out, err, n.Load())
	}
}

func TestSarinaSlowModelTimesOutWithoutRetryingTheChat(t *testing.T) {
	var chats atomic.Int32
	f := &svc{chat: func(w http.ResponseWriter) {
		chats.Add(1)
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte(`{"final_output":"too late"}`))
	}}
	srv := f.server(t)
	s, _ := NewSarina(srv.URL, "", "/tmp")
	s.http.Timeout = 100 * time.Millisecond
	s.retryDelay = time.Millisecond
	_, err := s.Advise(context.Background(), limboAlert("guest.start", "lab", detect.SeverityCritical))
	wantCode(t, err, CodeTimeout)
	if chats.Load() != 1 {
		t.Fatalf("a timed-out chat must not be repeated, got %d", chats.Load())
	}
	if !strings.Contains(f.all(), "DELETE /v1/sessions/s-1") {
		t.Fatal("session not closed after a timeout")
	}
}

func TestSarinaCancelledContextIsATimeoutNotAHang(t *testing.T) {
	f := &svc{chat: func(w http.ResponseWriter) { time.Sleep(300 * time.Millisecond) }}
	srv := f.server(t)
	s, _ := NewSarina(srv.URL, "", "/tmp")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := s.Advise(ctx, limboAlert("guest.start", "lab", detect.SeverityCritical))
	wantCode(t, err, CodeTimeout)
	if !strings.Contains(f.all(), "DELETE") {
		t.Fatal("cleanup must run even though the caller's context is already done")
	}
}

func TestSarinaHugeButBoundedReplyIsTruncatedToValidUTF8(t *testing.T) {
	f := &svc{chat: status(200, `{"final_output":"`+strings.Repeat("é", 100000)+`"}`)}
	out, err, _ := advise(t, f)
	if err != nil || len(out) > maxAdvice || !strings.HasPrefix(out, "é") {
		t.Fatalf("len=%d err=%v", len(out), err)
	}
	if strings.ContainsRune(out, '�') {
		t.Fatal("truncation split a rune")
	}
}

// --- Responder: failures reach the alert stream; advisories are bounded ---

type recSink struct {
	mu sync.Mutex
	as []alert.Alert
}

func (s *recSink) Write(a alert.Alert) error {
	s.mu.Lock()
	s.as = append(s.as, a)
	s.mu.Unlock()
	return nil
}
func (s *recSink) integration() []alert.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []alert.Alert
	for _, a := range s.as {
		if a.DetectorID == alert.IntegrationDetector {
			out = append(out, a)
		}
	}
	return out
}

func TestAdvisorFailureIsRecordedWithCodeAndRemedy(t *testing.T) {
	lim := &fakeLimbo{res: Result{Created: true, Applied: true, Record: Record{ID: "q-1"}}}
	next := &recSink{}
	r := &Responder{Next: next, Limbo: lim, Advisor: &fakeAdvisor{err: &SarinaError{CodeAuth, "401 Unauthorized", "set the token"}}}
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	r.Wait()
	got := next.integration()
	if len(got) != 1 {
		t.Fatalf("want one integration alert, got %d", len(got))
	}
	f := got[0].Fields
	if f["error_code"] != CodeAuth || f["remedy"] != "set the token" || f["quarantine"] != "q-1" || f["guest"] != "lab" {
		t.Fatalf("%v", f)
	}
	if !strings.HasPrefix(got[0].Summary, CodeAuth+": ") {
		t.Fatalf("summary should lead with the code: %q", got[0].Summary)
	}
}

type panicAdvisor struct{}

func (panicAdvisor) Advise(context.Context, alert.Alert) (string, error) { panic("boom") }

func TestAdvisorPanicDoesNotCrashTheDaemon(t *testing.T) {
	lim := &fakeLimbo{res: Result{Created: true, Applied: true, Record: Record{ID: "q-1"}}}
	next := &recSink{}
	r := &Responder{Next: next, Limbo: lim, Advisor: panicAdvisor{}}
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	r.Wait()
	if len(next.integration()) != 1 {
		t.Fatal("panic not recorded")
	}
}

type blockingAdvisor struct{ release chan struct{} }

func (b blockingAdvisor) Advise(context.Context, alert.Alert) (string, error) {
	<-b.release
	return "", nil
}

func TestAdvisoriesAreBoundedAndNeverBlockTheDetectionPath(t *testing.T) {
	lim := &fakeLimbo{res: Result{Created: true, Applied: true, Record: Record{ID: "q-1"}}}
	next := &recSink{}
	adv := blockingAdvisor{release: make(chan struct{})}
	r := &Responder{Next: next, Limbo: lim, Advisor: adv}
	done := make(chan struct{})
	go func() {
		for i := 0; i < maxAdvisories+3; i++ {
			r.Write(limboAlert("guest.start", fmt.Sprintf("lab%d", i), detect.SeverityCritical))
			waitIdleQuarantines(t, r) // quarantines finish at once; the advisories stay stuck
		}
		close(done)
	}()
	select {
	case <-done: // Write returned although every advisory is stuck on a slow model
	case <-time.After(3 * time.Second):
		t.Fatal("Write blocked behind a slow advisory")
	}
	busy := 0
	for _, a := range next.integration() {
		if a.Fields["error_code"] == CodeBusy {
			busy++
		}
	}
	if busy != 3 {
		t.Fatalf("want 3 skipped advisories recorded as %s, got %d", CodeBusy, busy)
	}
	close(adv.release)
	r.Wait()
}
