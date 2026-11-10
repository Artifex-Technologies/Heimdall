# Heimdall — architecture & roadmap

Heimdall is a security agent for [Sarina](https://github.com/Artifex-Technologies/Sarina),
built as a separate process on purpose: a security monitor that shares a
runtime, a dependency tree, or a crash with the thing it's watching is a
weaker monitor. Go was chosen over Python (Sarina's language) for the same
reason CrowdSec and Tailscale are Go and not Python — a single static
binary, no interpreter or GC-heavy runtime sitting between the monitor and
the host, low idle CPU/RAM for something meant to run forever in the
background. If Sarina itself moves toward Rust later, that only strengthens
the case for Heimdall staying a separate binary talking to it across a
process boundary rather than an in-process library.

**Every phase below is designed against a real reference project so the
design has a citation, not just a name-drop** — see
[`docs/REFERENCES.md`](REFERENCES.md) for the full, tracked ledger of
every reference used anywhere in this repo, kept up to date independently
of this file. All five phases are built as of 2026-11-05: Phase 3's mesh
(`MESH.md`), Phase 4's grant gate for escalations and access tiers
(`GRANTS.md`), and Phase 5's incidents and agent baseline were the last
pieces. What each deliberately leaves out is recorded in its section — see
[`CLAUDE.md`](../CLAUDE.md) before starting any of them, in case the plan
has since moved in the Coordination Log.

## Engine shape

Every phase, present and future, is meant to fit this same pipeline —
deliberately close to [CrowdSec](https://github.com/crowdsecurity/crowdsec)'s
parser → scenario → decision split, scoped down for a single agent instead
of a fleet:

```
   Source                Detector                    Sink
(produces Events)   (Events -> Findings)        (Findings -> Alerts)

agentsource.Watcher  ->  detect.Detector  ->  engine.Engine  ->  alert.Sink
  (Phase 1: reads          (injection,          (runs every          (stdout,
   Sarina's session          credential,          detector over        JSONL file,
   files as the kernel       unicode,             each Event in        in-memory ring
   reports changes)          escalation,          order)               for the API)
                             burst)
```

- **`internal/detect`** owns the shared vocabulary: `Event` (one
  observation, source-agnostic), `Finding` (a detector's verdict), and the
  `Detector` interface. A detector only ever sees `Event`s — it does not
  know or care whether they came from a session file (Phase 1), a file
  hash (Phase 2), or a connection log (Phase 3). This is what lets later
  phases add sources without touching existing detectors, and add
  detectors without touching existing sources.
- **`internal/sources/*`** are the only packages that know a specific
  format. `agentsource` knows the shape of a Sarina session file
  (`/var/lib/sarina/sessions/<id>.json`); `hostsource` knows `/proc/meminfo`, `/proc/loadavg`, and how to
  hash a watched file; `netsource` knows `/proc/net/tcp{,6}`'s column
  layout and the kernel's hex address encoding. None of the three knows
  the others exist, and detectors know none of them.
- **`internal/engine`** is the one package that imports both `detect` and
  `alert` — it runs each `Event` through every configured `Detector` in
  order and forwards `Finding`s to a `Sink`. Detectors run in-process,
  single-threaded, in delivery order, so a stateful detector (the burst
  counter) never needs its own locking.
- **`internal/alert`** turns a `Finding` into a timestamped `Alert` and
  fans it out to however many `Sink`s are configured — stdout always, an
  optional JSONL file, and an in-memory ring buffer the status API reads.
- **`internal/api`** is a loopback-only HTTP surface following the same
  "loopback only, no ecosystem service binds a routable interface by
  default" rule Sarina's `docs/ECOSYSTEM.md` already states for its own
  GUI/service ports. `/healthz`, `/v1/alerts`, `/v1/audit`, `/v1/quarantine`
  and `/v1/incidents` are read-only; `POST /v1/review` (Phase 4,
  `internal/governance`), `POST /v1/requests` (the grant gate: it files a
  request, it can never approve one) and `POST /v1/rules/drafts` (immunity:
  it keeps a draft, it can never install one) are the deliberate exceptions.
  Since 2026-11-05 every endpoint but `/healthz` answers only root, Heimdall's
  own account, `api_users` (default `sarina`) and members of `api_groups`
  (default `wheel`): the caller's account is read from the kernel's socket
  table (`/proc/net/tcp`, the client end of the loopback connection), so no
  client sends a token and none had to change (`internal/api/access.go`).

## Phase 1 — Agent-behavior monitoring (built)

Watches Sarina's session folder (`agent_session_dir`: `/var/lib/sarina/sessions`,
which the Sarina service writes; a workspace's `.port_sessions/agent/` has the
same shape) and raises an alert on:

| Detector | Catches | Ported from |
| --- | --- | --- |
| `injection-phrase` | Text that reads as an instruction override ("ignore all previous instructions", "you are now...") | Sarina's `sarina/memory_security.py` phrase list |
| `credential-shape` | Private keys, cloud/API tokens, password-looking assignments | Same file's credential patterns |
| `invisible-unicode` | Zero-width, bidi-override, isolate, or Unicode "tag" characters used to hide instructions from a human skim | Same file's invisible-character scan |
| `permission-escalation` | A session reporting one or more permission denials (the agent asked for a tool its tier disallows) | Sarina's own slash-command dispatch output |
| `session-burst` | An abnormal rate of new sessions in a sliding window | New to this repo — no fleet to compare against, so this looks at rate instead |

The injection/credential/unicode patterns are **deliberately the same
patterns Sarina already applies to its own curated-memory writes**
(`memory_security.py`). That file protects one write path inside Sarina;
Heimdall applies the identical threat model from outside, to everything a
session transcript contains, not only memory proposals. If Sarina's list
changes, update this one too — see the port-of-record note in
`internal/detect/injection.go` and `credential.go`.

**inotify, not polling (since 2026-11-09):** the first version polled, on
the reasoning that a single operator's folder sees a few writes a minute and
`os.Stat` per file is cheap. The folder turned out to hold thousands of
sessions (6,629 on my PC), so every 5 s cost a glob, 6,629 `stat`s and a
re-marshalled state file: 15.9 ms of CPU and 9.6 MB of garbage per poll.
Now the kernel's inotify (stdlib `syscall`, no `fsnotify` dependency, as
`vaultsource` already did) says which file was closed after writing, renamed
into place (how Sarina saves), created, or had its permissions changed, on the
folder and its `agent/` folder, and only that file is read
(`agentsource/watch.go`). A save is read at once; a file that keeps changing
at most once per `poll_interval_seconds`. The settle window stays: a file that
is not valid JSON yet is looked at again one interval later and reported as
damaged once it has not changed for 5 s. The whole folder is looked at on
start, after the kernel's event queue overflowed, when `agent/` appears, and
every 10 minutes in case an event was missed; while the folder cannot be
watched (missing, unreadable, no inotify) it is polled every interval as
before. The state file of read positions is written only when one changed.
Phase 2's FIM watcher still polls: a short, explicit list of files, one `stat`
each every 30 s.

**The text detectors run a pattern only where it can match (2026-11-09).**
Each `injection-phrase` and `credential-shape` pattern has the words it cannot
match without (`injectionLiterals`, `credentialLiterals`); the text is
case-folded once (ASCII, plus the long s and the Kelvin sign, the two letters
Go's `(?i)` folds onto ASCII ones) and a pattern runs, on the original text,
only when one of its words is there. `invisible-unicode` skips ASCII bytes
without decoding them and decodes `\u` escapes only when the text has one.
Findings are byte-identical: `prefilter_test.go` keeps the old code and runs
both on every file and line of this repository and on generated attacks
(random matches of every pattern, random case and fold letters, JSON-escaped,
with invisible and broken characters mixed in), about 53,000 texts. About 30
times less work on ordinary text; `RedactCredentials`, applied to every
alert, about 50 times.

**`session-burst` is a leaky bucket, not a timestamp list.** The first
version kept every `session_created` timestamp in a slice and re-pruned it
on every event — O(n) work and O(n) memory per call, growing with however
long the detector had been running. It's now two `float64`/`time.Time`
fields: a level that increments by one per event and drains continuously
at `threshold/window` per second, the same primitive CrowdSec's own
"leaky" bucket type uses. O(1) per event regardless of uptime. See
`internal/detect/burst.go`.

**Why the whole binary has zero third-party dependencies:** matches
Sarina's own core-agent rule (stdlib only; GUI/service add FastAPI, ML adds
onnxruntime, and only there) and keeps the Arch package's dependency graph
short, which matters directly for `packaging/arch/PKGBUILD` review and for
running reliably as an always-on systemd service.

## Phase 2 — Host telemetry & file integrity (built)

References: [Wazuh](https://github.com/wazuh/wazuh) (host-based FIM, log
analysis, XDR agent architecture) and
[Netdata](https://github.com/netdata/netdata) (per-second host metrics
from lightweight, mostly-`/proc`-reading collectors, not agents that shell
out).

`internal/sources/hostsource` has two independent watchers:

- **File integrity (`fim.go`).** Polls a short, explicit list of paths
  configured in `fim_paths` — each ecosystem repo's `CLAUDE.md`,
  `pyproject.toml`/`PKGBUILD`, systemd units — for unexpected
  modification or deletion. **The efficiency technique is Wazuh syscheck's:**
  a cheap mtime+size comparison decides whether a file needs rehashing at
  all, so an unchanged file (the common case on every poll) costs one
  `os.Stat` and nothing else; only a path whose mtime or size actually
  moved gets read and SHA-256 hashed. A first observation of any path
  establishes a silent baseline rather than alerting — there is nothing to
  compare against yet.

  **Baselines persist to `fim_state_path` (JSON, atomic write-then-rename).**
  This was a real bug caught while testing, not a design taken on faith: a
  first version kept baselines in memory only, so every `heimdalld scan`
  invocation — a fresh process each time — and every `heimdalld run` restart
  silently re-established a "first observation" baseline instead of
  comparing against history, meaning a genuine tamper occurring between
  two invocations, or right around a restart, would never be reported.
  Verified fixed with a regression test
  (`TestFIMWatcherPersistsBaselineAcrossInstances`) that constructs two
  separate `FIMWatcher` instances the way two separate process invocations
  would, and confirms the second one detects a change the first one
  couldn't have known about.

- **Host telemetry (`telemetry.go`).** Reads `/proc/meminfo` (`MemAvailable`,
  not `MemFree` — it already accounts for reclaimable cache) and
  `/proc/loadavg`, on an interval, into a `host_telemetry` Event. **CPU
  pressure uses load-average-per-core, not a `/proc/stat` jiffy-delta
  computation** — Netdata's own collectors compute precise per-core CPU%
  this way, but that needs a kept previous sample and delta math; load
  average needs one read and no state, and load-per-core past 1.0 is
  already a well-understood "more runnable work than the host can execute
  right now" signal. Linux-only target (see "Arch, specifically" below)
  means there's no cross-platform fallback to write — `TelemetryWatcher.Run`
  simply logs once and stops if `/proc` doesn't exist, rather than
  retrying forever against a platform that will never have it.

  The `resource-pressure` detector consuming these Events is
  edge-triggered (alerts once when a threshold is crossed, stays quiet
  until it clears) rather than re-alerting every poll during a sustained
  condition — this is Heimdall's own reliability signal as much as a new
  detection surface: sustained pressure is exactly the condition under
  which Heimdall's own polls might start lagging.

## Phase 3 — Network monitoring & mesh (built)

References: [Zeek](https://github.com/zeek/zeek) (turns raw traffic into
structured, protocol-aware connection logs rather than raw packet dumps —
the reference for *how* to observe, not a suggestion to embed a full
protocol-analysis engine) and [Tailscale](https://github.com/tailscale/tailscale)
(WireGuard mesh with identity-based ACLs — the reference for how several
Artifex Ecosystem machines' Heimdall instances might one day share alerts
directly with each other over a private mesh, the way CrowdSec's central
API lets community signals cross instances).

**Built: `internal/sources/netsource`.** Polls `/proc/net/tcp` and
`/proc/net/tcp6` — the same source `ss`/`netstat` read from — for
violations of the ecosystem-wide rule every repo's own `CLAUDE.md` already
states: *"loopback only, no ecosystem service binds a routable interface by
default."* Two checks against the ecosystem's own claimed ports (8765,
8899, 44700, 8930 — see Sarina's `docs/ECOSYSTEM.md` §6 port registry):

- **`non_loopback_bind`** — one of these ports is `LISTEN`ing on an address
  that isn't loopback (`0.0.0.0`/`::` included — that's the worst case, not
  an exception).
- **`non_loopback_peer`** — one of these ports has an `ESTABLISHED`
  connection whose remote address isn't loopback.

Both are exactly Zeek's framing applied at the smallest useful scale for
this project: a connection's *state* (who, which port, listening vs.
established) is the whole signal needed here, so this reads text columns
out of two `/proc` files rather than opening a raw socket or linking a
capture library — the same "no full packet capture" boundary the original
plan set. State-transition tracking (alert once when a violation appears,
not once per poll while it persists) lives in the source
(`netsource.PortWatcher`), the same split Phase 2's `FIMWatcher` uses, with
the detector (`NetworkExposureDetector`) staying a thin, stateless
translator.

**One read of the tables for every watcher (2026-11-09):** this check, the
connection log and the new-listener check each used to read and parse
`/proc/net/tcp{,6}` on their own clock. `netsource.Tables` reads them once per
interval (the shortest any of them asks for: 10 s with the connection log,
else 15 s) and hands the same read to each; a watcher with a longer interval
looks at every read that is at least that far, less half an interval, after
its last. Each keeps its behaviour (this check and the listener check learn on
their first look). The API's caller check (`internal/api/access.go`) still
reads the table itself: it needs the socket of the request being answered.

**Unlike FIM, this state is not persisted to disk, and that's deliberate,
not an oversight** — verified by testing both side by side on real Arch
Linux (see `progress.md`). File integrity is inherently a *diff against
history*: without a saved baseline, "did this file change" has no answer
at all across two separate `heimdalld scan` processes. A bind or connection
violation needs no history — "is this port listening on a non-loopback
address right now" is a complete, correct answer from a single snapshot.
So a persistent violation correctly reports once per long-lived `heimdalld
run` process (in-memory state, edge-triggered), but reports again on every
separate `heimdalld scan` invocation, the same way the Phase 1 message
detectors re-inspect every message in every session file on every `scan`
regardless of whether a prior invocation already saw it. `scan` is a
stateless "what does this look like right now" report; only `run` does
change-over-time suppression, and only where the underlying question is
actually about change (FIM) rather than current state (network exposure,
message content).

**Built 2026-11-05: the mesh half (`internal/mesh`, [`MESH.md`](MESH.md)).**
The trust question that kept it unplanned (whose server, what data leaves the
machine) is answered by having no server at all: each instance has an ed25519
key, the owner enrols peers by fingerprint and IP address in a root-owned
file on each computer, and instances talk mutual TLS 1.3 directly. The mesh
carries one thing, alert summaries, and a received alert is only shown, never
acted on. Designed against the October 2026 "Tailworm" flaws: no SSH, Serve,
Funnel, relay or coordination-server equivalents exist to have holes. Off by
default. headscale and Tailscale stay design references (the
self-hosted-control and identity-pinning ideas), not code.

## Phase 4 — Review & governance layer (built)

References: [CodeStrike](https://github.com/CrowdStrike/codestrike)
(chain-of-thought LLM review of a diff before it lands),
[Paperclip](https://github.com/paperclipai/paperclip) (an org-chart-style
control plane for a fleet of AI agents: budgets, approval workflows,
governance instead of one more chat window), and
[OpenExecutive](https://github.com/SenteLabsAI/OpenExecutive) (many
specialist agents behind one coherent decision-making voice). None of
these are security-monitoring tools — they're referenced here for the
**approval-gate pattern**, not for fleet orchestration or PR review, which
are out of scope.

Sarina already has a miniature version of this shape:
`sarina/memory_review.py` stages agent-proposed memory entries and requires
an explicit `memory-review-approve` before anything is written. Phase 4
generalizes that pattern *outward*, one call site at a time — the point of
moving it here is architectural, not redundancy: the agent being secured
should not be the sole process that decides its own action is fine.

**Built: `internal/governance` + `POST /v1/review`, consulted from
Sarina's shared scan gate (`go/guard`, through `go/heimdall`).** Every memory
write Sarina's own gate already checks (`guard.Memory()`: interactive memory
writes and automated memory proposals go through the same gate, so there is
exactly one gate to reason about) now also gets an out-of-process second
opinion from Heimdall, *after* Sarina's in-process checks pass. `governance.Reviewer`
runs the same three content detectors Phase 1 already has
(`injection-phrase`, `credential-shape`, `invisible-unicode`) against the
proposed text and returns `{"decision": "allow"|"deny", "reasons": [...]}`;
a deny folds into the same blocked result the in-process checks already
produce, so nothing downstream of the gate needed to change. Every
consultation — allowed or denied — is also recorded as an alert
(`source: "governance-review"`), so it shows up in `/v1/alerts` and
`alert_log_path` like anything else Heimdall detects. (The first version,
2026-09-26, was Sarina's legacy Python `sarina/memory_security.py`; the Go
core replaced it.)

**Why out-of-process is the actual point, not a formality.** Sarina's own
in-process check and Heimdall's copy currently run the identical three
pattern lists — today, if one catches something the other would too. The
value isn't redundancy against a bug in the regex; it's that Heimdall's copy
runs in a separate OS process Sarina cannot reach into, so a compromised or
sufficiently manipulated agent session that somehow disabled or bypassed
its own gate still can't touch Heimdall's independent copy.

**Deliberately fail-open on absence, fail-closed on an actual verdict.**
Sarina's `heimdall.Consult` returns nothing — not an error, not a block —
when `HEIMDALL_REVIEW_URL` is unset (the old name `SENTRY_REVIEW_URL` is still
read when the new one is unset) or Heimdall is unreachable; the gate then
falls back to its own in-process result exactly as before this integration
existed. Heimdall is optional infrastructure with no hard dependency in either
direction (`go/heimdall` uses only the Go standard library), but an actual
`"decision": "deny"` response is respected, not treated as a suggestion.

**Built 2026-11-05: the grant gate for escalations and access tiers
(`internal/grants`, [`GRANTS.md`](GRANTS.md)).** The old plan waited for
`escalation_runtime.py` to get one gate; that Python is gone, and Sarina's Go
core already has the property: every hand-off to another model tier goes
through `tiers.Router.attempt`, every default permission through
`config.AccessTierFromEnv`. Both now read the owner's decisions from
`/etc/heimdall/grants.json`, which only root writes (`heimdalld grant`), and
Sarina files requests over `POST /v1/requests`. A decision needs root, a
terminal, and no Sarina process among the deciding command's ancestors, so
Sarina can ask but never approve. Unlike the memory review, which fails open
when Heimdall is absent, the gate fails closed: an untrusted or damaged
decisions file allows nothing.

**Verified end-to-end, not just unit-tested in each repo separately:** a
real `heimdalld run` process with `api_addr` set, and real Python code in a
Sarina checkout calling `consult_sentry`/`scan_memory_text` against it
over loopback HTTP — an injection phrase sent from Python came back denied
with Heimdall's own detector's exact reason string, and appeared in
`/v1/alerts` with the session id threaded through correctly. See
`progress.md` for the full verification log.

## Phase 5 — ML / pattern recognition (built: baselines and incidents)

References: [TensorFlow](https://github.com/tensorflow/tensorflow),
[DeepVariant](https://github.com/google/deepvariant), and
[TALON](https://github.com/mortazavilab/TALON) (see
[`docs/REFERENCES.md`](REFERENCES.md) for the full, tracked reference
ledger this phase and every other one draws on). DeepVariant's
transferable idea is not genomics — it's turning a *sequence* of discrete
reads into a fixed-shape representation (a "pileup image") a small
convolutional model scores, rather than hand-written per-base rules.
TALON's is classifying an observed read against a *learned baseline* of
known transcript models by a distinguishing signature, rather than a
fixed rule, and reporting known-vs-novel rather than a bare match/no-match.
The Phase 1-4 detectors are all hand-written rules (regex, thresholds,
fixed percentages); Phase 5 adds judgment relative to *learned* history.

**Built: `internal/detect/stats.go` + `baseline.go` (`baseline-drift`).**
Online mean/variance via Welford's algorithm (`OnlineStats`, O(1) memory
and per-sample work — no history array to keep or prune) tracks a running
baseline for the same `host_telemetry` fields (`mem_percent`,
`load_per_cpu`) the Phase 2 `resource-pressure` detector already
consumes, no new source needed. A value more than `baseline_z_threshold`
standard deviations from the learned mean — not a fixed percentage
anyone had to pick in advance — fires once per crossing (edge-triggered,
same convention as `resource-pressure`).

**This is genuinely simple streaming statistics, described that way on
purpose — not an overclaimed "ML" feature.** No model, no training step,
no vendored framework. That's still squarely TALON's transferable idea
(classify an observation against a learned baseline instead of a fixed
rule) done honestly at the smallest scope that's actually useful: a host
that idles at 85% memory has a different "unusual" than one that idles at
20%, and only a learned baseline — not a fixed threshold — can tell them
apart.

**Known limitation, accepted for this slice:** every sample folds into
the baseline whether or not it was flagged, so a sustained shift
eventually becomes the new "normal" rather than staying flagged forever.
The alternative (a baseline that never adapts) would eventually flag
every reboot's warm-up period and every legitimate long-term usage change
— worse for a single always-on host than occasionally normalizing to a
real, sustained shift.

**A real calibration finding from live testing, not a hypothetical:**
verified on real Arch Linux (WSL2) with a genuine CPU load spike (see
`progress.md`), the detector correctly fired on both `load_per_cpu`
(baseline mean 0.00, stddev 0.01 on a near-idle host — a bump to just
0.02 was already 3.6 standard deviations out) and `mem_percent` (baseline
mean 18.14%, stddev 0.02 — a shift to 18.28% was 5.9 standard deviations
out). Both are correct behavior, not bugs: on a very stable, near-idle
host the natural noise floor is tiny, so the *default* `baseline_z_threshold`
of 3.0 can flag what's actually a small, unremarkable absolute change. An
operator running Heimdall on a consistently idle machine may want to raise
`baseline_z_threshold` above the default; this is a real, observed
characteristic of z-score-based detection on a low-variance signal, not
something a fixed default can fully paper over.

**Follow Sarina's own precedent if this ever needs an actual model, not
TensorFlow directly:** Sarina evaluated vendoring TensorFlow Lite for
`sarina/ml/`, found it 1GB+ installed and TF Lite itself in maintenance
mode, and shipped [ONNX Runtime](https://github.com/onnx/onnx) instead
(~30MB, CPU-only, offline at inference). Any future local model Heimdall
scores against should follow the same reasoning — this phase is not a
license to add a gigabyte-scale ML dependency to a security daemon meant
to run at all times. Not currently planned: this slice's simple
statistics already cover the "learned baseline" idea without one.

**Built 2026-11-05: incidents (`internal/correlate`).** Correlating
findings across detectors (a governance denial, a burst and a network event
from the same session, close together) is a graph problem:
[microsoft/graphrag](https://github.com/microsoft/graphrag)'s graph
construction, not its LLM half, is the idea taken. Every alert names entities
(a session, a guest, an address, a file, a pid or program, a tool, a request);
alerts sharing one within 30 minutes are one incident, a bridging alert merges
two, and an incident spanning two or more detectors with a warning raises one
`incident` alert (`GET /v1/incidents` lists them). It is a sink wrapper: no
work between alerts.

**Built 2026-11-05: the agent's own baseline (`detect.AgentBaselineDetector`).**
The same Welford statistics over what the agent does: sessions started and
tool calls made per 15-minute window while active, judged as the window fills,
plus a tool it has never used before once it has 200 tool calls of history
(TALON's known-vs-novel idea, applied to tool names). Info severity.

**Calibration with this PC's real data (2026-11-05).** Replaying 5067 real
Sarina sessions (2026-10-15 to 11-05) through the agent baseline: at z = 3,
five window findings in three weeks, all during eval runs (34-75 sessions in
a window against a mean of 8-22); at z = 4 or 5, one. Twenty-six
never-used-before tools, each one added during development, plus one the
model invented (`TaskOutput`). Host `baseline-drift` from the journal: 44
alerts since 10-15, but with today's floors (load 1.5 per CPU, memory 85 %)
only 5 in 19 days (z 3.0, 4.2, 7.4, 8.0, 8.0). On this 16-CPU machine the
learned load stddev in those alerts was 0.11-0.48 per CPU; half an hour of
fresh samples on 11-05 gave load mean 0.08, stddev 0.06 per CPU and memory
mean 11.3 %, stddev 0.7. Without the floors, z = 3 would have flagged four
ordinary half-minutes in that half hour; with them, none. So the floor
decides, not z. `baseline_z_threshold` stays 3.0: raising it to 4 would drop
only the 3.0 alert, which came during a sustained heavy period, the most
meaningful of the five.

## Arch, specifically

This project targets Arch Linux (Labyrinth OS and LykanOS, formerly Chymaera OS) as its only
supported platform — not "Linux and best-effort elsewhere." That
simplifies Phase 2/3 meaningfully: no cross-platform `/proc` abstraction to
write, no Windows-vs-Linux branch to test (contrast Sarina's own
Linux-is-reference/Windows-is-best-effort split, which exists only because
Sarina itself is cross-platform). `packaging/arch/` is the maintained
source of truth for the systemd unit and package metadata, mirroring
Sarina's own `packaging/arch/` layout so the distro's build tooling can
treat every Artifex repo's Arch packaging the same way.

## Connection log (per process, no packet capture)

`netsource.ConnWatcher` (internal/sources/netsource/conn.go) answers "which program talks to which address". It reads the
established TCP sockets from `/proc/net/tcp{,6}` (the inode of each) and finds the owner by looking for that inode in
`/proc/<pid>/fd`; the owner's cgroup gives the Labyrinth app id (`lapp_<id>.slice`). It sees addresses and ports only, never
contents, and it ignores loopback.

- Each (process, remote address, port) is reported once, the first time, and remembered in `conn_state_path`. The first run
  with no state file only learns what is already connected (events marked `learning`, no finding), so a fresh install does
  not start with a flood.
- `ConnectionDetector` findings: **critical** when an app whose network was switched off in Settings (read from
  `app_network_policy`) connects (the rule is not in force, usually the app needs a restart), **critical** when Sarina,
  Heimdall or Limbo connect off the machine (the ecosystem rule is loopback only), **warning** for ollama (model downloads),
  **info** for any other new destination.
- A socket's owner is looked for once (2026-11-09). Reading the link of every open file of every process every 10 s was most
  of the watcher's cost (5.7 ms a look on a desktop's worth of processes, more on a busy one). Owners are kept by socket inode,
  unfound ones too (a process Heimdall cannot look into does not cause a walk every look), and forgotten when the connection
  closes. `/proc/<pid>/fd` is walked only when a socket appears that has not been looked for, starting with the processes that
  hold the most connections (a browser opens the next one too) and stopping once every new socket is found. A socket two
  processes share (after a fork) is named after the first one found. A churn test checks the events are the same as with a
  walk every look.
- Seeing other users' processes needs `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, both read-only here:
  `packaging/arch/heimdall-connwatch.conf.example`. Without it connections are logged with the process shown as `unknown`.
- Config: `conn_watch` (default true), `conn_poll_interval_seconds` (10), `conn_state_path`, `app_network_policy`.
- Not covered: UDP (DNS, QUIC), connections that open and close between two polls (10 s), and which domain an address belongs to.
  A packet capture (Wireshark/tcpdump, installed by hand) is the tool for those; Heimdall deliberately does not embed one.

## Malware scanning (groundwork)

`internal/scan` is the engine; `heimdalld scan-files [--state F] [--exclude P]... [--max-mb N] PATH...` runs it by hand. It needs ClamAV
(`pacman -S clamav`, `freshclam` for signatures; on Labyrinth OS, Heimdall's component in Agora and the installer brings ClamAV and
switches its signature updates on, since 2026-11-05); without it the command says so and exits 2. Decisions:

- **Runs as the user whose files it reads.** A home folder is not readable by the `heimdall` system user (and the unit has ProtectHome), so the
  scan of Downloads is a per-user job (a user service or on demand from Settings), and its findings reach the desktop as notifications.
- **Reports, never moves.** Quarantine, "restore / delete / always allow" are desktop actions (notification buttons exist now).
- **Exclusions are first-class:** a folder, a file or a glob; the state file skips unchanged files (an infected file is reported once).
- **Done 2026-10-16:** ClamAV installed here (signatures update through clamav-freshclam.service); tested with the EICAR test file (found), an exclusion (skipped) and the remembered state (unchanged files skipped); one ClamAV run scans a whole batch (clamscan loads the signatures on every start, about 7 s; the clamd daemon, `systemctl enable --now clamav-daemon`, keeps them loaded and makes it fast but uses about 1-2 GB of memory, so it is off).
- **Built on Labyrinth OS's side:** the per-user service (`labyrinth-scan-downloads`: the places files arrive, every ten minutes and
  on arrival) and, since 2026-11-07, the weekly scan of the whole home folder (`--full`, `labyrinth-scan-full.timer`, Sunday
  afternoon on AC power, idle priority; caches, game libraries, toolchains, build output and disk images left out; it reports,
  and moves nothing outside the arrival places).
- **Not yet:** scanning a package's files after install (pacman hook),
  sending suspicious unknowns to a Limbo guest, and the exclusions list in Settings. See Labyrinth_OS docs/SECURITY_ROADMAP.md.

## Limbo guests: lifecycle, network, exchange

Limbo (the sandbox) writes an append-only event log (Limbo's docs/EVENTS.md); `internal/sources/limbosource` tails it. Three
detectors read it, each keeping no state beyond what the lifecycle check needs:

- `limbo-guest`: Limbo's own safety ordering, checked from outside (a guest started with no firewall policy loaded first, a
  policy removed under a running guest), plus `image.rejected` and `gate.blocked`.
- `limbo-network` (2026-11-05): `net.anomaly` is Limbo's own judgement that a guest's refused packets look like probing.
  `host_probe` (this computer) and `lan_probe` (the home network, the router, other guests) are critical; `scan` and `ipv6`
  warnings; an unknown reason a warning; `net.capped` info. `net.flow` (allowed traffic) and `net.blocked` (one refusal) are
  never alerts: Limbo already counts refusals and reports the pattern as `net.anomaly`, so an alert per refusal would say the
  same thing twice, and allowed traffic is what the guest's policy is for.
- `limbo-exchange` (2026-11-05): `exchange.held` (ClamAV knew a file a guest tried to hand out) is a warning, `exchange.fail`
  info, `exchange.file` nothing. The guest's path is renamed `guest_path`: in the rest of Heimdall `path` is a file on this
  computer, and the correlator links alerts that share one.

Separate detector IDs matter for incidents: the correlator reports an incident when two detectors share a key, so a guest
that probes this computer and also tries to hand out malware becomes one story through `guest:<name>`.

**Response.** Where the response is on (`limbo_control_socket` set and `limbo_auto_quarantine` true), `internal/response`
asks Limbo to restrict the guest (`level: restrict`: deny-all firewall, the guest keeps running and stays inspectable) for
`limbo-guest` criticals on `guest.start`/`policy.remove`, and for `limbo-network` `net.anomaly` with reason `host_probe`,
`lan_probe` or `scan` at warning or above (so a maintenance window that softens it to info also stops the response). A probe
is not cleared by a later `guest.stop` or `policy.apply`: the guest still went looking for a way out, and Limbo will not
start a guest it holds. `ipv6` (dropped, no route exists) and `exchange.held` (the file was already kept back) are alerts only.
Limbo limits how often it writes each of these (an anomaly at most once per guest and reason per 10 minutes, 256 flow events
per guest), so nothing here counts or times anything: no polling beyond the existing log tail.

**Held files.** `sudo heimdalld immunity take-limbo SHA256` copies a file Limbo held into Heimdall's immunity store
(`IMMUNITY.md`). Doing it automatically is a proposal there, because the daemon cannot write to root's request queue today.

## Running light (phase 0 of the Rust port, 2026-11-09)

I game and run a local AI model on the same computer, and want every bit of it for them. A measurement study found where
heimdalld's 0.95 % of a core and 71 MB went on my PC; these are the fixes in the Go code, and the design the Rust port keeps.

- **Event-driven where the kernel can say what changed.** Sarina's sessions (inotify, a full look every 10 minutes), vault
  notes (inotify), the journal (one `journalctl --follow`, `fwsource`). Polling is left only where nothing can tell
  (`/proc/net`, `/proc/meminfo`, the FIM list), each at its interval, and `/proc/net/tcp{,6}` is read once for all three
  network watchers (`netsource.Tables`).
- **Work only for what is new.** A socket's owner is looked for once (`ConnWatcher.owned`); a session file is read only when
  it changed; the state files are written only when something changed.
- **Big read-only data is mapped, not copied.** The IP databases are `mmap`ed read-only (`ipintel.Open`): the pages a lookup
  touches are the kernel's page cache, shared and reclaimable, not heimdalld's heap (they were about 40 MB of it). The
  reader's checks are unchanged; a file cut short in place while mapped faults, and `debug.SetPanicOnFault` turns that into
  an error from the lookup, as for any damaged file. An update renames a new file over the old one, so the mapping of the
  old one stays valid until the Resolver reopens and nothing uses it (a cleanup unmaps it).
- **Cheap checks before expensive ones.** The text detectors' patterns run only on text holding a word they cannot match
  without (Phase 1 section).
- **Long audits wait for games; watching never does.** The package audit, the kernel audit and the hardening checks (each
  every 6 hours) ask Yggdrasil's game time first (`internal/gametime`: `/usr/bin/yggdrasil-gametime status` exits 0 while a
  game runs). During a game the job logs one line and asks again every 5 minutes. Without the tool they run as before.
  Alerts, every detector, the sources and the Limbo responder keep running during games.
- **The smallest share when the computer is busy.** `heimdall.service` has `CPUWeight=20`, `IOWeight=20`, `Nice=10`; the
  other units likewise, except `heimdall-contain` (stopping a compromised agent must be quick).

**Measured** (the old and the new daemon side by side on the same synthetic load, in a network namespace of their own: 6,629
session files, 25 watched files, 40 MB of synthetic IP databases, the connection, listener and port watchers; 240 s after a
45 s warm-up, at nice 15; "activity" adds connections opening and closing and planted events: an injection and a key in a
tool result, a zero-width space in a growing session, a password in an old-shape session, a Limbo guest started without a
policy, a changed watched file, a poisoned vault note, a port bound off loopback and a new listener):

| | before | after |
| --- | --- | --- |
| idle: CPU | 0.579 % of a core | 0.046 % (12.6 times less) |
| idle: context switches | 10.2 a second | 2.1 a second |
| idle: PSS | 118.7 MB (110.2 MB heap and other anonymous memory) | 23.5 MB (14.9 MB) |
| activity: CPU | 0.538 % of a core | 0.075 % (7.2 times less) |
| activity: context switches | 12.2 a second | 5.3 a second |
| activity: PSS | 120.3 MB | 24.7 MB |
| activity: alerts | 77 | 77, identical once the time each was raised is dropped |

Of the 40 MB of mapped IP databases, 168 kB were resident after the run's lookups. The study's own run on my PC measured
0.60 % of a core and 72.5 MB PSS before, 0.16 % and 32 MB with a prototype of the first and third fixes only.

Single parts, by benchmark (i9-9900K, nice 15): a look at 6,629 sessions 15.9 ms and 9.6 MB of garbage every 5 s before,
now a full look every 10 minutes (11.4 ms) and 0.56 µs plus the file for a save; socket owners 5.7 ms every 10 s before,
4.6 µs when nothing is new, 0.76 ms for a new connection; the text detectors about 30 times less work on ordinary text;
`journalctl` 4.2 ms CPU per start, 4 starts a minute before, the follower 0.009 % of a core.

## The Rust port (2026-11-10, in progress)

The always-on daemon is being ported to Rust (`rust/`, `heimdalld-rs`) for less memory and CPU while I game and run a local
model; the design above carries over unchanged. It must raise the same alerts as this daemon on the same input: Go's JSON
leniency, Go's `%q`, Unicode tables generated from Go and Go's ASCII meaning of `\b \s \d \w` are reproduced, the Go table
tests are exported as fixtures both languages run (`internal/parity`, `testdata/parity`), and the regex and engine
differentials compare the two on hundreds of thousands of inputs. The text detectors' patterns are a typed rule file there
(`rust/heimdall/rules/text.json`), checked at load, kept equal to the patterns here by a Go test. Step 1 (detectors, engine,
alerts, config) and step 2 (every source on one thread, the 6-hourly audits on a second, behind game time) are done, and of
step 3 the correlator, governance, the API with its caller check and grants; the shadow week beside this daemon runs on my
PC (`docs/RUST_SHADOW.md`). Next: the last API endpoints and the Limbo responder, then mesh and trust. Plan, decisions and
numbers: `docs/RUST_PORT.md`.
