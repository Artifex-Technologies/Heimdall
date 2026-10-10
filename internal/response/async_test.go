package response

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// waitIdleQuarantines waits until no quarantine call is in flight, without
// waiting for advisories.
func waitIdleQuarantines(t *testing.T, r *Responder) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.inflight) + len(r.pending)
		r.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("quarantine calls never finished")
}

// hangLimbo is a Quarantiner whose socket hangs: every call announces itself on
// started and then blocks until release is closed or its context ends.
type hangLimbo struct {
	started chan string
	release chan struct{}
	calls   atomic.Int32
	ctxErr  chan error
	onCall  func()
}

func newHangLimbo() *hangLimbo {
	return &hangLimbo{started: make(chan string, 64), release: make(chan struct{}), ctxErr: make(chan error, 64)}
}

func (h *hangLimbo) Quarantine(ctx context.Context, guest, _, _ string, _ map[string]string) (Result, error) {
	h.calls.Add(1)
	if h.onCall != nil {
		h.onCall()
	}
	h.started <- guest
	select {
	case <-h.release:
		return Result{Applied: true, Record: Record{ID: "q-1"}}, nil
	case <-ctx.Done():
		h.ctxErr <- ctx.Err()
		return Result{}, ctx.Err()
	}
}
func (h *hangLimbo) Advise(context.Context, string, string, string) error { return nil }

func waitStarted(t *testing.T, h *hangLimbo) string {
	t.Helper()
	select {
	case g := <-h.started:
		return g
	case <-time.After(2 * time.Second):
		t.Fatal("no quarantine request was issued")
		return ""
	}
}

func errorCodes(s *recSink) []string {
	var out []string
	for _, a := range s.integration() {
		out = append(out, a.Fields["error_code"])
	}
	return out
}

func TestWriteReturnsQuicklyWhileLimboHangsAndAlertIsStoredFirst(t *testing.T) {
	next, lim := &recSink{}, newHangLimbo()
	var storedBeforeCall atomic.Bool
	lim.onCall = func() {
		next.mu.Lock()
		defer next.mu.Unlock()
		storedBeforeCall.Store(len(next.as) == 1 && next.as[0].DetectorID == "limbo-guest")
	}
	r := &Responder{Next: next, Limbo: lim}
	defer func() { close(lim.release); r.Wait() }()

	start := time.Now()
	if err := r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("Write blocked %v behind a hung Limbo socket", d)
	}
	if g := waitStarted(t, lim); g != "lab" { // issued promptly, no artificial delay
		t.Fatalf("quarantine for %q", g)
	}
	if !storedBeforeCall.Load() {
		t.Fatal("the alert must be stored before Limbo is called")
	}
}

func TestTriggerForAGuestAlreadyInFlightIsCoalesced(t *testing.T) {
	next, lim := &recSink{}, newHangLimbo()
	r := &Responder{Next: next, Limbo: lim}
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	waitStarted(t, lim)
	r.Write(limboAlert("policy.remove", "lab", detect.SeverityCritical))
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	next.mu.Lock()
	stored := len(next.as)
	next.mu.Unlock()
	if stored != 3 {
		t.Fatalf("every alert must still be stored, got %d", stored)
	}
	if n := lim.calls.Load(); n != 1 {
		t.Fatalf("%d concurrent quarantine calls for one guest", n)
	}
	close(lim.release)
	r.Wait()
	// Once the first has finished, a new trigger is a new call.
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	r.Wait()
	if n := lim.calls.Load(); n != 2 {
		t.Fatalf("want 2 calls in total, got %d", n)
	}
}

func TestConcurrentQuarantinesAreCapped(t *testing.T) {
	next, lim := &recSink{}, newHangLimbo()
	r := &Responder{Next: next, Limbo: lim}
	extra := 3
	for i := 0; i < maxQuarantines+extra; i++ {
		r.Write(limboAlert("guest.start", fmt.Sprintf("g%d", i), detect.SeverityCritical))
	}
	for i := 0; i < maxQuarantines; i++ {
		waitStarted(t, lim)
	}
	time.Sleep(20 * time.Millisecond)
	if n := lim.calls.Load(); n != maxQuarantines {
		t.Fatalf("%d calls in flight, cap is %d", n, maxQuarantines)
	}
	// The extras wait in the queue; nothing is dropped or recorded as "NOT requested".
	r.mu.Lock()
	queued := len(r.pending)
	r.mu.Unlock()
	if queued != extra {
		t.Fatalf("want %d queued requests, got %d", extra, queued)
	}
	if codes := errorCodes(next); len(codes) != 0 {
		t.Fatalf("waiting is not a failure, got %v", codes)
	}
	close(lim.release)
	r.Wait()
	if n := lim.calls.Load(); n != maxQuarantines+int32(extra) {
		t.Fatalf("every queued request must eventually be sent, got %d calls", n)
	}
}

func TestSlowSocketIsRecordedAsTimeoutWithRemedy(t *testing.T) {
	next, lim := &recSink{}, newHangLimbo()
	r := &Responder{Next: next, Limbo: lim, QuarantineTimeout: 50 * time.Millisecond}
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	r.Wait()
	got := next.integration()
	if len(got) != 1 || got[0].Fields["error_code"] != CodeLimboQuarantineTimeout || got[0].Fields["remedy"] == "" || got[0].Fields["guest"] != "lab" {
		t.Fatalf("%+v", got)
	}
}

func TestLimboFailureCodesAgainstARealClient(t *testing.T) {
	hang := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-hang:
		}
	}))
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"nft failed"}`))
	}))
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close() // nothing listens any more: a refused connection
	defer bad.Close()
	defer slow.Close()
	defer close(hang)

	tests := []struct{ name, url, want string }{
		{"hung socket", slow.URL, CodeLimboQuarantineTimeout},
		{"unreachable socket", goneURL, CodeLimboUnreachable},
		{"limbo answers with an error", bad.URL, CodeLimboQuarantineFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := &recSink{}
			r := &Responder{Next: next, Limbo: NewClientHTTP(tc.url, &http.Client{}), QuarantineTimeout: 200 * time.Millisecond}
			r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
			r.Wait()
			got := next.integration()
			if len(got) != 1 || got[0].Fields["error_code"] != tc.want || got[0].Fields["remedy"] == "" {
				t.Fatalf("want %s, got %+v", tc.want, got)
			}
		})
	}
}

func TestSuccessIsLoggedNotAlertedAndKeepsWhoAndWhat(t *testing.T) {
	next := &recSink{}
	var mu sync.Mutex
	var gotSource, gotReason string
	lim := &captureLimbo{fn: func(guest, reason, source string) { mu.Lock(); gotSource, gotReason = source, reason; mu.Unlock() }}
	r := &Responder{Next: next, Limbo: lim}
	a := limboAlert("guest.start", "lab", detect.SeverityCritical)
	r.Write(a)
	r.Wait()
	mu.Lock()
	defer mu.Unlock()
	if gotSource != "heimdall:limbo-guest" || gotReason != a.Summary {
		t.Fatalf("record would not show who/what: %q %q", gotSource, gotReason)
	}
	if len(next.integration()) != 0 {
		t.Fatal("a successful quarantine must not raise an integration alert")
	}
}

type captureLimbo struct{ fn func(guest, reason, source string) }

func (c *captureLimbo) Quarantine(_ context.Context, guest, reason, source string, _ map[string]string) (Result, error) {
	c.fn(guest, reason, source)
	return Result{Applied: true, Record: Record{ID: "q-1"}}, nil
}
func (c *captureLimbo) Advise(context.Context, string, string, string) error { return nil }

func TestShutdownCancelsAndAbandonsInFlightQuarantines(t *testing.T) {
	next, lim := &recSink{}, newHangLimbo()
	r := &Responder{Next: next, Limbo: lim}
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	waitStarted(t, lim)

	start := time.Now()
	if !r.Shutdown(50 * time.Millisecond) {
		t.Fatal("a call that honours its context should be gone after cancellation")
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Fatalf("shutdown took %v", d)
	}
	select {
	case err := <-lim.ctxErr:
		if err != context.Canceled {
			t.Fatalf("context ended with %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the in-flight call's context was never cancelled")
	}
	if len(next.integration()) != 0 {
		t.Fatalf("an abandoned call is not a Limbo fault: %v", errorCodes(next))
	}
	// Nothing new starts once shutting down, and nothing panics.
	r.Write(limboAlert("guest.start", "other", detect.SeverityCritical))
	time.Sleep(10 * time.Millisecond)
	if n := lim.calls.Load(); n != 1 {
		t.Fatalf("a quarantine started after shutdown: %d calls", n)
	}
}

func TestShutdownWaitsForACallThatFinishesWithinTheGrace(t *testing.T) {
	next, lim := &recSink{}, newHangLimbo()
	r := &Responder{Next: next, Limbo: lim}
	r.Write(limboAlert("guest.start", "lab", detect.SeverityCritical))
	waitStarted(t, lim)
	go func() { time.Sleep(30 * time.Millisecond); close(lim.release) }()
	if !r.Shutdown(2 * time.Second) {
		t.Fatal("shutdown did not wait for the in-flight call")
	}
	select {
	case err := <-lim.ctxErr:
		t.Fatalf("call was cancelled although it finished in time: %v", err)
	default:
	}
}

var _ alert.Sink = (*Responder)(nil)
