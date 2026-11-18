package response

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// analysisSvc is a scripted sarina-service for the analysis session: the create reply, the chat reply (or a hang), and
// every request with its body.
type analysisSvc struct {
	mu     sync.Mutex
	calls  []string
	create string
	chat   string
	hang   bool
}

func (f *analysisSvc) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path+" "+string(b))
		f.mu.Unlock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/sessions":
			w.Write([]byte(f.create))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/chat"):
			if f.hang {
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				return
			}
			w.Write([]byte(f.chat))
		case r.Method == "DELETE":
			w.Write([]byte(`{"evicted":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *analysisSvc) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

func TestTheAnalysisSessionHasOnlyReverseEngineerAndIsClosed(t *testing.T) {
	f := &analysisSvc{create: `{"session_id":"s-9","tools":1}`, chat: `{"final_output":"ELF, downloads a second stage","stop_reason":"completed"}`}
	s, _ := NewSarina(f.server(t).URL, "", "/var/lib/heimdall")
	out, err := s.Analyse(context.Background(), "look at /quarantine/x.sample")
	if err != nil || out != "ELF, downloads a second stage" {
		t.Fatalf("%q %v", out, err)
	}
	all := f.all()
	for _, want := range []string{`"tool_allowlist":["reverse_engineer"]`, `"allow_shell":false`, `"allow_write":false`, `"max_tool_calls":10`,
		"POST /v1/sessions/s-9/chat", "DELETE /v1/sessions/s-9"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
}

// Exactly one tool: none means the service has not switched reverse_engineer on (she could only guess), more means it
// ignored the allowlist (an older service) and would hand her every tool.
func TestTheFileIsNotSentUnlessTheSessionHasExactlyThatOneTool(t *testing.T) {
	for _, create := range []string{`{"session_id":"s-1"}`, `{"session_id":"s-1","tools":0}`, `{"session_id":"s-1","tools":2}`, `{"session_id":"s-1","tools":70}`} {
		f := &analysisSvc{create: create, chat: `{"final_output":"x"}`}
		s, _ := NewSarina(f.server(t).URL, "", "/tmp")
		out, err := s.Analyse(context.Background(), "look")
		wantCode(t, err, CodeToolsMismatch)
		all := f.all()
		if out != "" || strings.Contains(all, "/chat") || !strings.Contains(all, "DELETE /v1/sessions/s-1") {
			t.Fatalf("%s: out=%q calls:\n%s", create, out, all)
		}
	}
	// the advisory keeps its own check and words
	f := &analysisSvc{create: `{"session_id":"s-1","tools":1}`, chat: `{"final_output":"x"}`}
	s, _ := NewSarina(f.server(t).URL, "", "/tmp")
	if _, err := s.AdviseBacklog(context.Background(), "3 waiting"); err == nil || !strings.Contains(err.Error(), "did not confirm a tool-less session") {
		t.Fatal(err)
	}
}

func TestASlowAnalysisTimesOutAndTheSessionIsStillClosed(t *testing.T) {
	f := &analysisSvc{create: `{"session_id":"s-2","tools":1}`, hang: true}
	s, _ := NewSarina(f.server(t).URL, "", "/tmp")
	s.SetTimeout(100 * time.Millisecond)
	_, err := s.Analyse(context.Background(), "look")
	wantCode(t, err, CodeTimeout)
	if all := f.all(); !strings.Contains(all, "DELETE /v1/sessions/s-2") {
		t.Fatal(all)
	}
}

func TestAnAnalysisAnswerIsBoundedValidText(t *testing.T) {
	f := &analysisSvc{create: `{"session_id":"s-3","tools":1}`, chat: `{"final_output":"` + strings.Repeat("ü", 40<<10) + `"}`}
	s, _ := NewSarina(f.server(t).URL, "", "/tmp")
	out, err := s.Analyse(context.Background(), "look")
	if err != nil || len(out) > maxAnalysis || len(out) < maxAnalysis-1 || !strings.HasPrefix(strings.Repeat("ü", 40<<10), out) {
		t.Fatal(len(out), err)
	}
}
