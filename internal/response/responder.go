package response

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// triggerKinds are the Limbo events that mean a guest that is running (or about
// to) is outside its safety rules, so there is something to cut off. Events like
// image.rejected describe a guest that never started and are deliberately not
// here: there is nothing running to quarantine.
var triggerKinds = map[string]bool{
	"guest.start":   true, // started with no firewall policy applied first
	"policy.remove": true, // firewall removed while the guest was running
}

// guestRe mirrors Limbo's name rule. The name came from a log file, so it is
// checked again before being put on a request.
var guestRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,11}$`)

// Quarantiner is what the responder needs from Limbo.
type Quarantiner interface {
	Quarantine(ctx context.Context, guest, reason, source string, evidence map[string]string) (Result, error)
	Advise(ctx context.Context, id, source, text string) error
}

// Stable codes for Limbo-side failures (docs/INTEGRATION-FAILURES.md).
const (
	CodeLimboQuarantineFailed  = "limbo_quarantine_failed"
	CodeLimboQuarantineTimeout = "limbo_quarantine_timeout"
	CodeLimboUnreachable       = "limbo_unreachable"
)

const (
	// maxQuarantines caps concurrent Limbo quarantine calls, so a flood of
	// detections cannot spawn unbounded goroutines against a hung socket. Requests
	// beyond the cap wait in the pending queue; they are never dropped.
	maxQuarantines = 8

	// DefaultQuarantineTimeout bounds one quarantine call. It was 20 s when the
	// call blocked the engine loop; it now only holds a background goroutine, but
	// 10 s is still far above a healthy nft change (milliseconds) and keeps the
	// window in which a hung socket leaves a guest unrestricted short. It is also
	// below the Limbo HTTP client's own 15 s timeout, so this deadline is the one
	// that fires and classifies the failure.
	DefaultQuarantineTimeout = 10 * time.Second

	// maxAdvisories is how many Sarina consultations may run at once.
	maxAdvisories = 2

	// DefaultMaxPending is the hard sanity cap on distinct guests waiting. Requests
	// are coalesced per guest, so the queue is bounded by the number of guests;
	// reaching this means something is wrong, and it is recorded loudly.
	DefaultMaxPending = 1024
	// DefaultDelayThreshold is how long a request may wait before it is reported.
	DefaultDelayThreshold = 15 * time.Second
	// DefaultBacklogThreshold: more than this many waiting raises a backlog alert.
	DefaultBacklogThreshold = 4
	// DefaultBacklogInterval is the minimum gap between backlog alerts.
	DefaultBacklogInterval = time.Minute

	// statusTimeout bounds the read-only status call made before a request is sent.
	statusTimeout = 3 * time.Second
)

// Codes for the queue's own outcomes (docs/INTEGRATION-FAILURES.md).
const (
	CodeQuarantineDelayed    = "limbo_quarantine_delayed"
	CodeQuarantineBacklog    = "limbo_quarantine_backlog"
	CodeQuarantineOverflow   = "limbo_quarantine_overflow"
	CodeQuarantineSkipped    = "quarantine_skipped"
	CodeNotCompletedShutdown = "quarantine_not_completed_at_shutdown"
	CodeBacklogAdvisory      = "quarantine_backlog_advisory"
)

// StatusChecker is an optional, read-only extension of Quarantiner: what Limbo
// currently holds for a guest. found is false when there is no holding record.
// level is Limbo's strongest level among the guest's holding records and opened
// the newest record at that level. A Quarantiner without it just means the
// re-check cannot learn this, and the request proceeds.
type StatusChecker interface {
	QuarantineStatus(ctx context.Context, guest string) (level string, opened time.Time, found bool, err error)
}

// BacklogAdvisor is an optional extension of Advisor that comments on the queue
// backlog for a human. Its answer is an untrusted note and nothing more.
type BacklogAdvisor interface {
	AdviseBacklog(ctx context.Context, summary string) (string, error)
}

// request is one pending quarantine. Triggers for the same guest are merged
// into it, so there is at most one per guest.
type request struct {
	guest    string
	primary  alert.Alert // the most severe alert merged so far (the first of equals)
	enqueued time.Time   // when the first trigger arrived; orders equal severities
	latest   time.Time   // alert time of the newest merged trigger
	seq      uint64      // sequence number of the newest merged trigger
	kinds    []string    // distinct event kinds merged, in arrival order
	count    int         // triggers merged
	delayed  bool        // limbo_quarantine_delayed already raised
}

// mark notes that a guest's situation changed at some sequence number.
type mark struct {
	seq    uint64
	reason string
}

func severityRank(s detect.Severity) int {
	switch s {
	case detect.SeverityCritical:
		return 3
	case detect.SeverityWarning:
		return 2
	case detect.SeverityInfo:
		return 1
	}
	return 0
}

// before reports whether a is served before b: more severe first, then oldest.
func before(a, b *request) bool {
	if ra, rb := severityRank(a.primary.Severity), severityRank(b.primary.Severity); ra != rb {
		return ra > rb
	}
	if !a.enqueued.Equal(b.enqueued) {
		return a.enqueued.Before(b.enqueued)
	}
	return a.guest < b.guest
}

// Responder is an alert.Sink that forwards every alert unchanged and, for the
// narrow set that mean a Limbo guest is unsafe, also quarantines it.
//
// Forwarding comes first and never depends on the quarantine call: a Limbo
// outage must not cost Heimdall its own alerts. The quarantine itself is queued and
// run by at most maxQuarantines background workers, so a hung Limbo socket cannot
// stall the detection loop and a flood of detections cannot be dropped: excess
// requests wait, most severe first then oldest first (no model is involved in
// that order). Just before a request is sent it is re-checked read-only, and
// anything slow, skipped or unfinished is recorded in the alert stream.
type Responder struct {
	Next    alert.Sink
	Limbo   Quarantiner
	Advisor Advisor // optional
	Log     *log.Logger

	// QuarantineTimeout bounds one quarantine call; zero means
	// DefaultQuarantineTimeout.
	QuarantineTimeout time.Duration
	// MaxPending, DelayThreshold, BacklogThreshold and BacklogInterval default to
	// the Default* constants when zero.
	MaxPending       int
	DelayThreshold   time.Duration
	BacklogThreshold int
	BacklogInterval  time.Duration
	// MonitorTick is how often waiting requests are checked for the delay and
	// backlog alerts; zero means 1 s.
	MonitorTick time.Duration

	wg sync.WaitGroup // quarantine and advisory goroutines, so tests and shutdown can wait

	initOnce sync.Once
	ctx      context.Context // cancelled by Shutdown; parent of every background call
	cancel   context.CancelFunc
	slots    chan struct{} // bounds concurrent advisories so a burst cannot pile up long model calls

	mu          sync.Mutex
	pending     map[string]*request // queued, at most one per guest
	inflight    map[string]bool     // guests with a quarantine call in flight
	active      int                 // calls in flight (== len(inflight))
	seq         uint64              // orders triggers against observed Limbo events
	marks       map[string]mark     // newest "situation changed" event per guest
	lastBacklog time.Time
	closing     bool // set by Shutdown: no new triggers are accepted
}

func (r *Responder) init() {
	r.initOnce.Do(func() {
		r.ctx, r.cancel = context.WithCancel(context.Background())
		r.slots = make(chan struct{}, maxAdvisories)
		r.pending = map[string]*request{}
		r.inflight = map[string]bool{}
		r.marks = map[string]mark{}
		go r.monitor()
	})
}

func (r *Responder) maxPending() int {
	if r.MaxPending > 0 {
		return r.MaxPending
	}
	return DefaultMaxPending
}

func (r *Responder) delayThreshold() time.Duration {
	if r.DelayThreshold > 0 {
		return r.DelayThreshold
	}
	return DefaultDelayThreshold
}

func (r *Responder) backlogThreshold() int {
	if r.BacklogThreshold > 0 {
		return r.BacklogThreshold
	}
	return DefaultBacklogThreshold
}

func (r *Responder) backlogInterval() time.Duration {
	if r.BacklogInterval > 0 {
		return r.BacklogInterval
	}
	return DefaultBacklogInterval
}

// Write implements alert.Sink. The alert is stored first, always; the request is
// then queued and Write returns without waiting for Limbo.
func (r *Responder) Write(a alert.Alert) error {
	err := r.Next.Write(a)
	if !r.triggers(a) {
		return err
	}
	r.init()
	r.enqueue(a)
	return err
}

func (r *Responder) enqueue(a alert.Alert) {
	guest := a.Fields["guest"]
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		r.logf("guest %q: not quarantined, Heimdall is shutting down", guest)
		r.quarantineFailure(guest, CodeNotCompletedShutdown,
			fmt.Sprintf("quarantine of guest %q was not requested: Heimdall is shutting down", guest),
			"restrict the guest by hand with the Limbo CLI", map[string]string{"guests": guest})
		return
	}
	r.seq++
	if r.inflight[guest] {
		r.mu.Unlock()
		// One call per guest at a time; the one in flight already asserts the hold.
		r.logf("guest %q: quarantine already in flight, coalescing this trigger (%s)", guest, a.EventKind)
		return
	}
	if req, ok := r.pending[guest]; ok {
		// Merge, never drop: keep the most severe alert as the primary and remember
		// every trigger, so a repeat can raise the priority but never lower it.
		req.count++
		req.seq, req.latest = r.seq, a.Time
		if !containsStr(req.kinds, a.EventKind) {
			req.kinds = append(req.kinds, a.EventKind)
		}
		upgraded := severityRank(a.Severity) > severityRank(req.primary.Severity)
		if upgraded {
			req.primary = a
		}
		r.mu.Unlock()
		r.logf("guest %q: quarantine already queued, merged this trigger (%s, priority upgraded: %v)", guest, a.EventKind, upgraded)
		return
	}
	if len(r.pending) >= r.maxPending() {
		r.mu.Unlock()
		r.quarantineFailure(guest, CodeQuarantineOverflow,
			fmt.Sprintf("quarantine of guest %q NOT queued: %d other guests are already waiting", guest, r.maxPending()),
			"something is generating triggers for a very large number of guests; check Limbo (systemctl status limbo) and restrict the guest by hand", nil)
		return
	}
	r.pending[guest] = &request{guest: guest, primary: a, enqueued: time.Now(), latest: a.Time, seq: r.seq, kinds: []string{a.EventKind}, count: 1}
	r.dispatchLocked()
	r.mu.Unlock()
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// bestLocked returns the request to serve next, or nil.
func (r *Responder) bestLocked() *request {
	var best *request
	for _, q := range r.pending {
		if best == nil || before(q, best) {
			best = q
		}
	}
	return best
}

// dispatchLocked starts queued requests while worker slots are free. Callers hold
// r.mu. Once Shutdown has cancelled the context nothing new starts.
func (r *Responder) dispatchLocked() {
	for r.active < maxQuarantines && len(r.pending) > 0 && r.ctx.Err() == nil {
		q := r.bestLocked()
		delete(r.pending, q.guest)
		r.inflight[q.guest] = true
		r.active++
		r.wg.Add(1)
		go r.quarantine(q)
	}
}

// Observe feeds a Limbo event to the re-check. It only records, per guest, that a
// later event (policy re-applied, guest stopped) may have cleared the condition
// that triggered a queued request; it never acts. Call it after the engine has
// handled the same event, so a trigger is ordered before what follows it.
func (r *Responder) Observe(e detect.Event) {
	if e.Source != "limbo" {
		return
	}
	guest := e.Fields["guest"]
	if !guestRe.MatchString(guest) {
		return
	}
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	switch e.Kind {
	case "policy.apply":
		r.marks[guest] = mark{r.seq, "the firewall policy was applied again after the trigger"}
	case "guest.stop":
		r.marks[guest] = mark{r.seq, "the guest stopped after the trigger, so nothing is running to quarantine"}
	case "guest.start":
		delete(r.marks, guest) // running again: whatever was cleared no longer is
	}
}

// recheck decides, just before the Limbo call, whether the request is still
// needed. It uses only information Heimdall already has (the Observe marks) and one
// read-only Limbo list call. Anything it cannot determine means "proceed": it
// fails toward acting, never toward skipping.
func (r *Responder) recheck(q *request) (skip bool, reason string) {
	r.mu.Lock()
	m, ok := r.marks[q.guest]
	r.mu.Unlock()
	if ok && m.seq > q.seq {
		return true, m.reason
	}
	sc, ok := r.Limbo.(StatusChecker)
	if !ok {
		return false, ""
	}
	ctx, cancel := context.WithTimeout(r.ctx, statusTimeout)
	defer cancel()
	level, opened, found, err := sc.QuarantineStatus(ctx, q.guest)
	if err != nil {
		r.logf("guest %q: quarantine status unknown (%v), proceeding", q.guest, err)
		return false, ""
	}
	if !found {
		return false, ""
	}
	switch level {
	case "isolate":
		// The link is down independently of the firewall: stricter than what we ask for.
		return true, "Limbo already holds the guest at level isolate"
	case "restrict":
		// A hold opened before the newest trigger may predate the very change that
		// triggered this (e.g. the policy being removed); re-asserting it is the
		// point of repeating a request. Only a hold opened after it is "done".
		if !opened.Before(q.latest) {
			return true, "Limbo already holds the guest at level restrict, opened after the trigger"
		}
	}
	return false, ""
}

func (r *Responder) quarantine(q *request) {
	guest := q.guest
	defer func() {
		r.mu.Lock()
		delete(r.inflight, guest)
		r.active--
		r.dispatchLocked()
		r.mu.Unlock()
		r.wg.Done()
	}()
	defer func() {
		if p := recover(); p != nil { // background work must never take the daemon down
			r.quarantineFailure(guest, CodeLimboQuarantineFailed, fmt.Sprint("quarantine call panicked: ", p), "report this as a Heimdall bug", nil)
		}
	}()

	wait := time.Since(q.enqueued).Round(time.Millisecond)
	waitField := map[string]string{"queue_wait": wait.String()}
	if skip, reason := r.recheck(q); skip {
		r.logf("guest %q: quarantine skipped after %s in queue: %s", guest, wait, reason)
		r.quarantineFailure(guest, CodeQuarantineSkipped,
			fmt.Sprintf("quarantine of guest %q not sent: %s", guest, reason),
			"none needed if the guest is as restricted as intended; check it with the Limbo CLI",
			map[string]string{"queue_wait": wait.String(), "reason": reason})
		return
	}

	timeout := r.QuarantineTimeout
	if timeout <= 0 {
		timeout = DefaultQuarantineTimeout
	}
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	a := q.primary
	reason := a.Summary
	if q.count > 1 {
		reason = fmt.Sprintf("%s (%d triggers merged: %s)", a.Summary, q.count, strings.Join(q.kinds, ", "))
	}
	res, qerr := r.Limbo.Quarantine(ctx, guest, reason, "sentry:"+a.DetectorID, map[string]string{
		"detector": a.DetectorID, "event_kind": a.EventKind, "alert_time": a.Time.Format(time.RFC3339),
		"queue_wait": wait.String(), "triggers": strings.Join(q.kinds, ","),
	})
	if qerr != nil {
		if r.ctx.Err() != nil { // abandoned by shutdown: not a Limbo fault
			r.logf("guest %q: quarantine abandoned at shutdown: %v", guest, qerr)
			return
		}
		code, remedy := classifyQuarantineError(qerr)
		r.quarantineFailure(guest, code, fmt.Sprintf("could not quarantine guest %q: %v (queue wait %s)", guest, qerr, wait), remedy, waitField)
		return
	}
	if !res.Applied {
		// Recorded but not enforced (e.g. the nft change failed). Say so loudly:
		// "quarantined" must not be reported for a guest that still has a route.
		r.logf("guest %q: quarantine %s recorded but NOT enforced: %s (queue wait %s)", guest, res.Record.ID, res.Error, wait)
	} else {
		r.logf("guest %q quarantined (%s, level %s, queue wait %s)", guest, res.Record.ID, res.Record.Level, wait)
	}
	// Only the first alert for an incident asks for an opinion; repeats just
	// re-assert the hold.
	if res.Created && r.Advisor != nil {
		select {
		case r.slots <- struct{}{}:
			r.wg.Add(1)
			go r.advise(res.Record.ID, a)
		default:
			// Never queue behind slow model calls; the human still has the evidence.
			r.integrationAlert(res.Record.ID, guest, CodeBusy, "skipped the Sarina advisory: other advisories are still running", "wait for them to finish; the quarantine itself is unaffected")
		}
	}
}

// monitor makes lateness visible: a request waiting past DelayThreshold is
// reported once, and while more than BacklogThreshold wait a backlog alert is
// raised at most once per BacklogInterval. It stops when Shutdown cancels.
func (r *Responder) monitor() {
	tick := r.MonitorTick
	if tick <= 0 {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-t.C:
			r.sweep(now)
		}
	}
}

func (r *Responder) sweep(now time.Time) {
	type late struct {
		guest string
		wait  time.Duration
	}
	var lates []late
	r.mu.Lock()
	waiting, running := len(r.pending), r.active
	for _, q := range r.pending {
		if !q.delayed && now.Sub(q.enqueued) >= r.delayThreshold() {
			q.delayed = true
			lates = append(lates, late{q.guest, now.Sub(q.enqueued).Round(time.Millisecond)})
		}
	}
	var backlog []*request
	if waiting > r.backlogThreshold() && (r.lastBacklog.IsZero() || now.Sub(r.lastBacklog) >= r.backlogInterval()) {
		r.lastBacklog = now
		for _, q := range r.pending {
			c := *q
			backlog = append(backlog, &c)
		}
	}
	r.mu.Unlock()

	sort.Slice(lates, func(i, j int) bool { return lates[i].guest < lates[j].guest })
	for _, l := range lates {
		r.quarantineFailure(l.guest, CodeQuarantineDelayed,
			fmt.Sprintf("quarantine request for guest %q has waited %s in the queue (%d waiting, %d in flight)", l.guest, l.wait, waiting, running),
			"Limbo is answering slower than detections arrive; check limbo_quarantine_timeout / limbo_unreachable alerts and 'systemctl status limbo'; restrict the guest by hand if it is critical",
			map[string]string{"queue_wait": l.wait.String(), "backlog": strconv.Itoa(waiting)})
	}
	if backlog != nil {
		r.raiseBacklog(backlog, running, now)
	}
}

func (r *Responder) raiseBacklog(backlog []*request, running int, now time.Time) {
	sort.Slice(backlog, func(i, j int) bool { return before(backlog[i], backlog[j]) })
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d quarantine requests waiting, %d in flight (at most %d run at once). Waiting, in service order:\n", len(backlog), running, maxQuarantines)
	guests := make([]string, 0, len(backlog))
	for i, q := range backlog {
		guests = append(guests, q.guest)
		if i < 20 {
			fmt.Fprintf(&sb, "- %s severity=%s triggers=%s waited=%s\n", q.guest, q.primary.Severity, strings.Join(q.kinds, ","), now.Sub(q.enqueued).Round(time.Second))
		}
	}
	r.quarantineFailure(strings.Join(guests, ","), CodeQuarantineBacklog,
		fmt.Sprintf("%d quarantine requests are waiting for Limbo (%d in flight)", len(backlog), running),
		"check that Limbo is responding (systemctl status limbo, limbo_quarantine_timeout alerts); restrict the most severe guests by hand",
		map[string]string{"backlog": strconv.Itoa(len(backlog)), "guests": strings.Join(guests, ","), "in_flight": strconv.Itoa(running)})

	ba, ok := r.Advisor.(BacklogAdvisor)
	if !ok {
		return
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	select {
	case r.slots <- struct{}{}:
		r.wg.Add(1)
		r.mu.Unlock()
	default:
		r.mu.Unlock()
		return // the backlog alert stands on its own; never wait for a model
	}
	go r.adviseBacklog(ba, sb.String(), now)
}

// adviseBacklog asks for ONE untrusted note about the backlog and records it as
// its own alert. It changes nothing: no ordering, no skipping, no action.
func (r *Responder) adviseBacklog(ba BacklogAdvisor, summary string, at time.Time) {
	defer r.wg.Done()
	defer func() { <-r.slots }()
	defer func() {
		if p := recover(); p != nil {
			r.logf("backlog advisor panicked: %v", p)
		}
	}()
	ctx, cancel := context.WithTimeout(r.ctx, 3*time.Minute)
	defer cancel()
	text, err := ba.AdviseBacklog(ctx, summary)
	if err != nil {
		code, msg, remedy := ErrorInfo(err)
		r.quarantineFailure("", code, "backlog advisory failed: "+msg, remedy, nil)
		return
	}
	text = strings.Map(func(c rune) rune {
		if c == '\n' || (c >= ' ' && c != 0x7f) {
			return c
		}
		return -1
	}, strings.ToValidUTF8(clip(text, 4000), ""))
	if strings.TrimSpace(text) == "" {
		return
	}
	r.quarantineFailure("", CodeBacklogAdvisory,
		"Sarina's note on the quarantine backlog raised at "+at.UTC().Format(time.RFC3339)+" (untrusted; it changed nothing)",
		"read it as a hint only; the backlog alert has the facts",
		map[string]string{"advisory": text, "untrusted": "true"})
}

// classifyQuarantineError maps a failed Limbo call to a stable code and remedy.
func classifyQuarantineError(err error) (code, remedy string) {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return CodeLimboQuarantineTimeout, "Limbo's socket did not answer in time; check that limbod is not hung (systemctl status limbo) and restrict the guest by hand if it is still running"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return CodeLimboUnreachable, "start Limbo (systemctl start limbo) and check limbo_control_socket in Heimdall's config; restrict the guest by hand meanwhile"
	}
	return CodeLimboQuarantineFailed, "read the message for Limbo's reason (journalctl -u limbo); restrict the guest by hand if it is still running"
}

// quarantineFailure records a failed, skipped, late or unfinished quarantine in
// the alert stream, with its stable code and remedy, after the original alert is
// already stored. extra adds fields beyond guest, error_code and remedy.
func (r *Responder) quarantineFailure(guest, code, msg, remedy string, extra map[string]string) {
	r.logf("%s: %s (remedy: %s)", code, msg, remedy)
	f := map[string]string{"guest": guest}
	for k, v := range extra {
		f[k] = v
	}
	if err := r.Next.Write(alert.Integration(code, msg, remedy, f)); err != nil {
		r.logf("could not record %s: %v", code, err)
	}
}

func (r *Responder) triggers(a alert.Alert) bool {
	return a.DetectorID == "limbo-guest" &&
		a.Severity == detect.SeverityCritical &&
		triggerKinds[a.EventKind] &&
		guestRe.MatchString(a.Fields["guest"])
}

func (r *Responder) advise(id string, a alert.Alert) {
	defer r.wg.Done()
	defer func() { <-r.slots }()
	defer func() {
		if p := recover(); p != nil { // advisory work must never take the daemon down
			r.integrationAlert(id, a.Fields["guest"], "sarina_error", fmt.Sprint("advisor panicked: ", p), "report this as a Heimdall bug")
		}
	}()
	ctx, cancel := context.WithTimeout(r.ctx, 3*time.Minute)
	defer cancel()
	text, err := r.Advisor.Advise(ctx, a)
	if err != nil {
		code, msg, remedy := ErrorInfo(err)
		r.integrationAlert(id, a.Fields["guest"], code, msg, remedy)
		return
	}
	if text == "" {
		return
	}
	if err := r.Limbo.Advise(ctx, id, "sarina", text); err != nil {
		r.logf("could not attach advisory to %s: %v", id, err)
	}
}

// integrationAlert records a failed Sarina consultation in the alert stream (not
// just the log), with its stable code and remedy. The human still has the
// quarantine and its evidence; only the advisory is missing.
func (r *Responder) integrationAlert(quarantineID, guest, code, msg, remedy string) {
	r.logf("sarina advisory for %s failed: %s: %s (remedy: %s)", quarantineID, code, msg, remedy)
	if err := r.Next.Write(alert.Integration(code, msg, remedy, map[string]string{"quarantine": quarantineID, "guest": guest})); err != nil {
		r.logf("could not record %s: %v", code, err)
	}
}

// Wait blocks until running quarantines (and everything still queued, which the
// workers pick up as they free) and advisories finish.
func (r *Responder) Wait() { r.wg.Wait() }

// Shutdown stops accepting triggers, waits up to grace for the queue to drain
// and for in-flight calls and advisories to finish, then cancels their context.
// Requests still queued at that point are recorded as one
// quarantine_not_completed_at_shutdown alert naming the guests, so they are not
// lost silently. It reports whether everything finished.
func (r *Responder) Shutdown(grace time.Duration) bool {
	r.init()
	r.mu.Lock()
	r.closing = true
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	finished := false
	select {
	case <-done:
		finished = true
	case <-time.After(grace):
	}
	r.cancel() // after this no queued request starts (dispatchLocked checks it)

	r.mu.Lock()
	left := make([]*request, 0, len(r.pending))
	for _, q := range r.pending {
		left = append(left, q)
	}
	r.pending = map[string]*request{}
	r.mu.Unlock()
	if len(left) > 0 {
		sort.Slice(left, func(i, j int) bool { return before(left[i], left[j]) })
		names := make([]string, len(left))
		for i, q := range left {
			names[i] = q.guest
		}
		list := strings.Join(names, ",")
		r.quarantineFailure(list, CodeNotCompletedShutdown,
			fmt.Sprintf("%d queued quarantine request(s) were not sent before Heimdall shut down: %s", len(left), list),
			"restrict these guests by hand with the Limbo CLI; Heimdall will not retry them after a restart",
			map[string]string{"guests": list, "count": strconv.Itoa(len(left))})
	}
	if !finished {
		select {
		case <-done:
			finished = true
		case <-time.After(time.Second):
		}
	}
	return finished && len(left) == 0
}

func (r *Responder) logf(format string, v ...any) {
	if r.Log != nil {
		r.Log.Printf(format, v...)
	}
}
