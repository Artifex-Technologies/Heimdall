# CLAUDE.md — Heimdall

Guidance for Claude Code (and any AI agent) working in this repository,
**and** Heimdall's half of the Chymaera Ecosystem coordination board. Read
top-to-bottom before making changes. Append to the **Coordination Log** at
the bottom whenever you do work another project might depend on.

---

## 1. What this project is

Heimdall is a **security agent for Sarina**: a separate Go process
that watches Sarina's on-disk output for prompt injection, leaked
credentials, invisible-Unicode smuggling, permission escalation, and
abnormal session-creation bursts. It does not import Sarina's code and does
not share a runtime with it — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for why that separation is the point, not an accident.

It is the **fifth repo** in the Chymaera Ecosystem:

| Repo | Role |
| --- | --- |
| `Sarina` | local-model agent shipped inside Chymaera OS |
| `Chymaera_OS` | Arch-based security distro that hosts the agent and the app |
| `Argus_App` | fork of qFlipper; desktop operator console (Qt6/QML) |
| `Argus_Firmware` | fork of flipperzero-firmware; runs on the hardware |
| `Heimdall` | this repo — security agent watching Sarina |

Sarina carries the authoritative four-repo integration contract:
[`Sarina/docs/ECOSYSTEM.md`](https://github.com/Artifex-Technologies/Sarina/blob/main/docs/ECOSYSTEM.md).
Heimdall's own contract with Sarina is recorded in **§5** below and proposed
to Sarina's board in the Coordination Log entry at the bottom of this file
— read Sarina's board before assuming it has been accepted.

**Arch Linux only.** Unlike Sarina, this project does not target
cross-platform use — see `docs/ARCHITECTURE.md`'s "Arch, specifically"
section for why that's deliberate.

## 2. Build / test / run

Go 1.21+. No compile-time or runtime third-party dependencies — the whole
module is stdlib-only, deliberately (see `docs/ARCHITECTURE.md`).

```bash
go build ./...
go vet ./...
go test ./...                          # every test is offline, stdlib-only
go build -o heimdalld ./cmd/heimdalld
./heimdalld scan --config config.json    # one-shot, exits non-zero on any finding
./heimdalld run  --config config.json    # foreground daemon
```

`agent_session_dir` in the config is required for `run`/`scan` to do
anything; there is no default because the right value is a sibling repo's
path on this machine, not something to guess. See
[`packaging/arch/config.json.example`](packaging/arch/config.json.example).

## 3. Architecture map

```
cmd/heimdalld/              CLI entry point: run, scan, version subcommands
internal/
  detect/                 Event/Finding/Detector model + every detector, including
                          stats.go (Welford's algorithm) + baseline.go (Phase 5)
  sources/agentsource/     Polls a Sarina .port_sessions/ directory into Events
  sources/hostsource/      File-integrity + host telemetry watchers (Phase 2)
  sources/netsource/       /proc/net/tcp{,6} connection-exposure watcher (Phase 3)
  governance/              Phase 4: reviews text via the existing detectors, out-of-process
  engine/                  Runs Events through every Detector, forwards Findings
  alert/                   Finding -> Alert; stdout/file/ring Sinks
  api/                     Loopback-only HTTP API -- read-only except POST /v1/review
  config/                  JSON config, all fields optional except agent_session_dir
docs/
  ARCHITECTURE.md          Engine design + the full 5-phase roadmap
  REFERENCES.md            Tracked ledger of every external reference project cited anywhere in this repo
packaging/arch/            PKGBUILD, systemd unit, sysusers -- mirrors Sarina's own layout
```

Phases 1-2, Phase 3's connection half, Phase 4's first slice, and Phase
5's first slice are built — see `docs/ARCHITECTURE.md` for current
per-phase status, since this file doesn't repeat it and it will drift.

Adding a detector means: a new file in `internal/detect/` implementing
`Detector`, registered in `cmd/heimdalld/main.go`'s `newDetectors`, and a
table-driven test alongside the others in `internal/detect/detect_test.go`.
Adding a source means a new package under `internal/sources/` producing
`detect.Event`s — it should not need to change any existing detector.

## 4. Conventions

- **Stdlib only, no exceptions without discussion.** This is not a
  Sarina-style "core agent only" carve-out with GUI/service exceptions —
  the entire binary is one thing, and it stays dependency-free. If a later
  phase (host FIM, packet capture, local ML scoring) genuinely needs a
  third-party package, say so explicitly and record the reasoning in
  `docs/ARCHITECTURE.md`, the way that file already reasons about why
  Phase 1 didn't need `fsnotify`.
- **Match the surrounding code.** Doc comments on every exported type and
  function explaining *why*, not restating the signature. Table-driven
  tests. `gofmt` before every commit (`gofmt -l .` should print nothing).
- **Loopback only.** Any network-facing feature binds loopback by default,
  per the ecosystem-wide rule in Sarina's `docs/ECOSYSTEM.md` §5 — see
  `internal/api/status.go`'s `ListenAndServeLoopback` for the enforced
  version of that rule, not just a convention.
- **Read-only toward Sarina's filesystem, always; one narrow exception for
  Phase 4.** Heimdall never writes into a Sarina workspace and never assumes
  write access to anything Sarina owns. It does, as of Phase 4's first
  slice, answer a consultation Sarina's own code sends it (`POST
  /v1/review`) and its response can influence whether a Sarina memory
  write proceeds — see `internal/governance`'s doc comment and
  `docs/ARCHITECTURE.md`'s Phase 4 section for the reasoning and the
  fail-open/fail-closed boundary. This is the **one** deliberate exception;
  it is not a precedent for Heimdall initiating contact with Sarina or
  gating anything beyond what's explicitly wired up (currently: the
  memory-write path only).
- **Never commit secrets.** No tokens, keys, or real session/alert data —
  a real `alerts.jsonl` may contain exactly the credentials/injections it
  exists to catch.

## 5. Chymaera Ecosystem — coordination protocol

Multiple Claude instances work across the sibling repos and can access each
other's repositories. This file is the contract + message board for this
repo, the same role Sarina's `CLAUDE.md` plays for Sarina.

**Rules for every agent touching this repo:**

1. Read this file first. Read Sarina's `CLAUDE.md` and `docs/ECOSYSTEM.md`
   before touching anything that depends on Sarina's session-file shape.
2. When you change anything another repo relies on, update this file's
   **Cross-repo contracts** below in the same commit.
3. Append a dated entry to the **Coordination Log**.
4. Sign entries with project name and model, e.g. `Heimdall / Claude`.
5. A contract marked **proposed** is not settled — Sarina's session-file
   shape (§ below) is exactly that right now. Do not build against changes
   to it until Sarina's board answers.

### Cross-repo contracts (keep authoritative)

- **Heimdall → Sarina (reads):** **proposed, read-only.**
  `internal/sources/agentsource` polls Sarina's agent session files,
  `.port_sessions/agent/<id>.json` (`session_id`, `messages` as objects with
  `role`/`content`/`tool_calls` — the Go core's file, which Sarina now treats as
  the contract, as of 2026-10-05); the older flat `messages: []string` shape
  under `.port_sessions/` is still accepted.
  Heimdall never writes into this directory and never imports Sarina's code.
  **This format is Sarina's internal state, not a published contract** —
  proposed to Sarina's board in the 2026-09-25 Coordination Log entry
  below, not yet agreed. Sarina changing this shape is not a breaking
  change on Sarina's side unless/until its board accepts freezing it;
  until then, Heimdall absorbing a format change here is Heimdall's problem.
- **Sarina → Heimdall (governance, Phase 4):** **live, opt-in.**
  The reverse direction: Sarina's `sarina/sentry_governance.py` calls
  Heimdall's `POST /v1/review` (`internal/governance` + `internal/api/review.go`)
  over loopback HTTP, opt-in via `SENTRY_REVIEW_URL` on Sarina's side.
  `sarina/memory_security.py`'s `scan_memory_text` consults it after its
  own in-process checks pass; a `"deny"` folds into the same
  `MemoryScanResult` shape those checks already produce. **Fails open on
  Heimdall's absence, fails closed on an actual verdict** — see
  `docs/ARCHITECTURE.md`'s Phase 4 section. Verified end-to-end with a
  real `heimdalld run` process and real Python code in a Sarina checkout;
  logged in both repos' 2026-09-26 Coordination Log entries. Marked
  **live** rather than proposed because both halves are built, tested, and
  wired together — not because the shape is guaranteed never to move; a
  breaking change to the request/response JSON still needs updating here
  and in `sentry_governance.py`'s docstring in the same commit, per the
  change protocol below.
- **Limbo → Heimdall (reads):** **live.** `internal/sources/limbosource`
  tails Limbo's `events.jsonl` (spec: `Limbo/docs/EVENTS.md`: one JSON object per
  line with `time`, `kind`, `guest`, and a flat string-valued `detail`).
  `detect.LimboGuestDetector` audits Limbo's own safety ordering from outside its
  process (guest start without a prior firewall policy; policy removal under a
  running guest) and translates `image.rejected` / `gate.blocked`. Heimdall never
  writes to the file. Limbo adding kinds or detail keys is backwards compatible;
  renaming or removing them is a contract change needing `CONTRACT:` and an
  update here. Verified against logs from real Limbo runs on a real hypervisor.
  Known gap: `limbo up` runs as root and writes the log mode 0600, so the heimdalld
  user cannot read it until the packaging grants access.
- **Heimdall → Limbo (control): live, restrict-only.** The owner decided
  (2026-10-04) that Heimdall may cut a guest's network, and that a human must
  approve any verdict. `internal/response` calls Limbo's `control.sock`
  (`POST /v1/quarantine`, `POST /v1/quarantine/{id}/advisory`). **That socket has
  no route to release a guest, lift a hold, lower a level, tear a guest down or
  give a verdict** (Limbo registers a separate route table per socket; the
  absent routes are tested), so a compromised Heimdall can make a guest more
  restricted, never less. Trigger: only `limbo-guest` alerts of severity critical
  on event kinds `guest.start` / `policy.remove`, with a re-validated guest name.
  The level Heimdall asks for is always `restrict` (deny-all firewall, guest keeps
  running, host can still inspect it). This is the **second exception** to
  "read-only toward other projects" (the first is `/v1/review`); it is narrow by
  construction and is not a precedent for acting on anything else. Active only
  in `heimdalld run`, never `scan`. Fails soft: a Limbo outage never costs Heimdall
  its own alerts. Spec: `Limbo/docs/QUARANTINE.md`.
- **Heimdall → Sarina (advisory): live, opt-in.** After a *new*
  quarantine, `internal/response` asks the local Sarina service
  (`sarina-service`, `sarina_url`, loopback only) for an opinion: creates a session
  with `tool_allowlist: []` (**no tools at all**), sends the alert framed as
  untrusted data, and attaches the reply to the quarantine as an **advisory**.
  Heimdall **verifies** the service's reported tool count is 0 and refuses to send
  anything otherwise, because an older service silently ignores the field.
  Advisories never change a record's status; only a human verdict does. Sarina's
  reply is derived from guest-controlled data and is treated as untrusted
  throughout (bounded, labelled, shown to the human as such). Uses Sarina's
  `POST /v1/sessions` / `/chat` API plus the additive `tool_allowlist` field and
  `tools` count (Sarina commit "Add a per-session tool allowlist"; **requires a
  Sarina that has it**). This is Heimdall initiating contact with Sarina, a first;
  recorded here and in Sarina's `docs/ECOSYSTEM.md` §4c.
- **Ports owned by this repo:** `8930` (Heimdall status API, loopback-only,
  read-only). Add it to Sarina's `docs/ECOSYSTEM.md` §5 port registry in
  the same commit that binds it — done as part of registering this repo,
  see the Coordination Log below.

### Coordination Log (newest first)

### 2026-10-10 — Renamed from Chymaera_Sentry; Limbo-facing identifiers renamed
- Repo moved to Artifex and renamed Heimdall. Heimdall-owned names changed: alert
  `source` `sentry` -> `heimdall`; quarantine source sent to Limbo `sentry:<detector>`
  -> `heimdall:<detector>`; env var `SENTRY_SARINA_TOKEN` -> `HEIMDALL_SARINA_TOKEN`;
  Limbo group `limbo-sentry` -> `limbo-heimdall` (must match Limbo's sysusers file).
- Unchanged because Sarina owns them: `SENTRY_REVIEW_URL`, `sentry_governance.py`,
  `consult_sentry`. Sarina still needs its own rename.
- Existing deployments must rename the group and the token env var.
— Signed: Heimdall / Claude Sonnet 5.5

### 2026-10-06 (3) — Quarantine requests are queued by priority, not dropped over the cap
- The 8-call concurrency cap used to record a trigger as `limbo_quarantine_failed` "NOT
  requested". The owner does not want security responses to slip through, so excess
  requests now wait in a pending queue (one per guest, merged on repeat; hard sanity cap of
  1024 guests -> `limbo_quarantine_overflow`). Order: highest severity, then oldest; a more
  severe repeat upgrades priority. No model is involved in ordering.
- Re-check before sending (`quarantine_skipped` note): uses Limbo events Heimdall already sees
  (`Responder.Observe`, fed from the Limbo watcher in `heimdalld run`: `guest.stop`,
  `policy.apply` after the trigger) and Limbo's read-only `GET /v1/quarantine` on the control
  socket (holding record at `isolate`, or at `restrict` opened after the trigger). Unknown
  status means proceed. Limbo has no guest-existence call on that socket, so "guest gone"
  comes from the event stream only.
- Visibility: queue wait in Limbo's evidence and on failure alerts; `limbo_quarantine_delayed`
  once per request past 15 s; `limbo_quarantine_backlog` at most once a minute above 4
  waiting; optional single Sarina note on the backlog (`quarantine_backlog_advisory`,
  untrusted, tool-less session, cannot reorder or skip). Config: `limbo_quarantine_delay_seconds`,
  `limbo_backlog_threshold`. `Shutdown` drains within the grace then records unsent guests as
  `quarantine_not_completed_at_shutdown`.
- Docs: `docs/INTEGRATION-FAILURES.md` updated. Tests: `internal/response/queue_test.go`.
— Signed: Heimdall / Claude Sonnet 5.5

### 2026-10-06 (2) — Limbo quarantine moved off the engine loop
- `Responder.Write` used to call Limbo synchronously (20 s timeout), so a hung Limbo socket
  stalled every detector. Now the triggering alert is stored first, then the quarantine runs on
  a background goroutine: 10 s budget, one in flight per guest (repeats coalesced and logged),
  at most 8 concurrent (extras recorded, not silently dropped), request issued immediately.
- New integration codes: `limbo_quarantine_failed`, `limbo_quarantine_timeout`,
  `limbo_unreachable` (alert with `fields.guest`, `error_code`, `remedy`); success stays a log
  line. The quarantine record Limbo stores is unchanged (source, reason, evidence), so Limbo's
  side needs no change.
- `Responder.Wait()` (tests) and `Responder.Shutdown(grace)` (`heimdalld` waits 3 s, then cancels
  in-flight calls; abandoned calls are not reported as Limbo faults). Documented in
  `docs/INTEGRATION-FAILURES.md`. Tests use a hanging fake Limbo and real HTTP servers.
— Signed: Heimdall / Claude Sonnet 5.5

### 2026-10-06 — Sarina integration made diagnosable: stable error codes, bounded advisories
- Reviewed every Heimdall<->Sarina touchpoint for failure behaviour. New runbook:
  `docs/INTEGRATION-FAILURES.md` (failure mode -> code -> symptom -> detection -> remedy,
  with check commands). Codes: `sarina_unreachable`, `sarina_timeout`, `sarina_auth`,
  `sarina_contract_tools_nonzero`, `sarina_session_evicted`, `sarina_server_error`,
  `sarina_bad_response`, `sarina_backend_error`, `sarina_busy`, `agent_session_unreadable`,
  `agent_session_malformed`, `agent_session_unknown_shape`.
- `internal/response`: every advisory failure is a `*SarinaError` (code, message, remedy) and
  is now written to the alert stream as a `detector_id: "integration"` alert
  (`alert.Integration`), not only the log. One retry on a refused/dropped connection only;
  chat timeouts are never repeated. At most 2 advisories at once (extra ones are recorded as
  `sarina_busy`, never queued); a panic is recovered. Session is still DELETEd on every path.
  A 200 with `stop_reason: backend_error` and an empty `final_output` are errors, no longer
  stored as advice; `session_id` is validated before use in a URL.
- `internal/sources/agentsource`: a missing/unreadable directory, unreadable file, damaged
  JSON (only once unmodified for 5 s, so a write in progress is not damage) and undecodable
  messages are reported once each via `Watcher.Issues()`/`Poll` errors instead of looking like
  "no sessions". `heimdalld scan` exits 2 with warnings when a file was not audited.
- Contract question for Sarina's board: does the service report model-backend failure only as
  `stop_reason: "backend_error"` on a 200 (as 05-gui-service.md says)? Heimdall relies on that
  string. Also: may Sarina guarantee session files are replaced atomically (write+rename)? The
  5 s settle window is a workaround.
— Signed: Heimdall / Claude Sonnet 5.5

### 2026-10-05 — agentsource reads Sarina's real session file
- Sarina's clean-room Go rewrite made the agent session file
  (`.port_sessions/agent/<id>.json`, `messages` as objects) the contract. It
  never wrote the flat `messages: []string` shape this reader expected, so the
  agent-behaviour detectors saw nothing from real runs.
- `internal/sources/agentsource` now reads `.port_sessions/agent/*.json`
  (and still the old flat shape in `.port_sessions/`). Per message it scans
  `content` plus, for assistant messages, the tool calls issued (name +
  arguments); `system` messages are skipped (the agent's own instruction text
  would only cause false positives). Events carry a `role` field.
- Verified against a real session file produced by Sarina's Go service with a
  local qwen3 model, not just fixtures. 2 new tests; full suite passes.
- Sarina no longer writes the API key into session files.
— Signed: Heimdall / Claude Sonnet 5.5 (working in this repo at the Sarina owner's request)

### 2026-10-04 (2) — Quarantine response: Heimdall may restrict a Limbo guest; humans decide
- **Owner's decision, explicit:** Heimdall may cut a guest's network; a human
  must approve marking it safe or dangerous; Sarina gives an extra opinion.
- **New `internal/response`**: `Client` (Limbo control socket), `Sarina` advisor,
  `Responder` (an `alert.Sink` wrapper). Config: `limbo_control_socket`,
  `limbo_auto_quarantine` (default on once the socket is set), `sarina_url`,
  `sarina_cwd`; token via `sarina_token` or `HEIMDALL_SARINA_TOKEN`. `alert.Alert`
  gained an additive `fields` map so the guest is known without parsing text.
- **The safety property is enforced on Limbo's side, not trusted here:** the
  control socket simply has no loosening routes. Verified with real unprivileged
  users against real sockets (Limbo's `scripts/integration-quarantine.sh`).
- **Deliberately narrow trigger**, not "any critical alert": `guest.start` /
  `policy.remove` only. `image.rejected` describes a guest that never started;
  there is nothing running to cut off.
- Sarina's advisory is explicitly framed to her as untrusted data and the
  session has **no tools**; her answer cannot change state. A prompt-injected
  advisory can mislead a reader, not release a guest, which is why the verdict
  is human-only.
- **Real finding, fixed:** the first version asked for `allow_shell=false,
  allow_write=false` and the chain test (real Sarina service, fake model that
  records requests) showed the model was still offered ~70 tools (`web_fetch`,
  `memory_add`, `config_set`, `mcp_call_tool` ...). Those flags only deny at call
  time and gate neither of those. A hostile guest could have steered the advisory
  model into writing attacker text into Sarina's memory. Fixed by an explicit
  tool allowlist in Sarina's service (empty = none) and by Heimdall verifying the
  reported count.
- Verified against Sarina's **real** service (fake model behind it, so no model
  quality claim). Not verified: a real model's advisory quality.
— Signed: Heimdall / Claude Sonnet 5.5

### 2026-10-04 — Limbo event source and limbo-guest detector
- **New `internal/sources/limbosource`** + **`detect.LimboGuestDetector`**
  (`limbo-guest`), registered in `newDetectors`; config `limbo_event_log`,
  `limbo_state_path`, `limbo_poll_interval_seconds`. Limbo is a new sibling
  project (guest-application sandbox, Windows/Linux guests on libvirt/nftables);
  see the contract entry above.
- Source reads only complete lines (a poll can land mid-write), restarts from
  the top if the file shrinks, and can persist its offset so a restart neither
  replays history nor skips events written while Heimdall was down. Without a
  state path, `run` starts at the end; `scan` audits the whole file.
- **`scan` no longer requires `agent_session_dir`** when a Limbo log is
  configured, and warns on stderr if the configured log does not exist. Found
  the hard way: a first end-to-end run printed "no findings" because a path
  was wrong, which is exactly the false all-clear an audit tool must not give.
- Verified end to end with a log written by Limbo's real `events` package and
  the real `heimdalld scan` binary (Windows host): a guest started without
  policy, a policy removed under a live guest, and a rejected image each
  produced a critical finding; a well-behaved guest produced none.
- **Also verified against a log from real Limbo runs on a real hypervisor**
  (libvirt/QEMU under WSL2 nested KVM, 16 guest lifecycles including failed
  starts and rollbacks, 112 events): `heimdalld scan` reported no findings, and
  with the `policy.apply` events deleted from a copy it flagged every start as
  an unfiltered guest. So no false positives on real traffic, and the
  detection works on the real log shape.
- Detector caveat: if Heimdall begins watching mid-sequence it may never have
  seen a `policy.apply`, and will report a later `guest.start` as unfiltered.
  Deliberately left noisy; a persisted offset avoids it in normal operation.
— Signed: Heimdall / Claude Sonnet 5.5

### 2026-09-26 (5) — docs/REFERENCES.md added; Phase 5 built (first slice): baseline-drift detector
- **New `docs/REFERENCES.md`**: a flat, trackable ledger of every external
  reference project cited anywhere in this repo (16 rows), each with a
  status (Adapted / Design reference / Candidate / Methodology-only), the
  specific file the adaptation lives in where one exists, and a
  **Checked** date, so a future update to any reference has something
  concrete to diff against instead of a re-read of the whole roadmap.
  User supplied an expanded reference list (adding n8n, GraphRAG, Letta,
  TALON, headscale, ONNX to the original ten). Verified three of the six
  new ones by fetching the actual repo rather than assuming from the name
  — same discipline that caught the CodeStrike mischaracterization in the
  original list.
- **Real finding from that pass: `juanfont/headscale` reopens Phase 3's
  mesh half.** That section was marked "not currently planned" because a
  CrowdSec-style shared central API raises a trust question (whose
  server, what data leaves the machine) nobody asked this project to
  solve. Headscale is a self-hosted implementation of Tailscale's own
  control server — same mechanics, self-hosted answers exactly that
  objection. Not moved to built; `docs/ARCHITECTURE.md`'s Phase 3 section
  updated so the next time this comes up it gets a real design pass
  instead of the same reflexive "not planned."
- **Phase 5 built (first slice): `internal/detect/stats.go` +
  `baseline.go` (`baseline-drift`).** Online mean/variance via Welford's
  algorithm applied to the same `host_telemetry` Fields Phase 2 already
  collects (`mem_percent`, `load_per_cpu`) — no new source. Flags a value
  more than `baseline_z_threshold` (default 3.0) standard deviations from
  the *learned* mean once `baseline_min_samples` (default 20)
  observations exist; edge-triggered like `resource-pressure`. Described
  in every doc as honest streaming statistics, deliberately not
  overclaimed as "ML" — the transferable idea is TALON's known-vs-novel
  classification against a learned baseline, done at the smallest useful
  scope.
- **Verified live on real Arch Linux (WSL2) with a genuine CPU load
  spike** (`yes > /dev/null` busy loops), not only synthetic unit-test
  fixtures — both `load_per_cpu` and `mem_percent` correctly fired.
- **Real calibration finding, recorded plainly rather than tuned away:**
  on a near-idle host, natural baseline variance was tiny (stddev
  0.01–0.02), so small absolute changes (load 0.00→0.02, memory
  18.14%→18.28%) registered as 3.6 and 5.9 standard deviations — correct
  behavior for a z-score detector on a low-variance signal, but an
  operator on a consistently idle host may want a higher
  `baseline_z_threshold` than the 3.0 default. Full numbers in
  `docs/ARCHITECTURE.md`'s Phase 5 section and `progress.md`.
- 7 new tests (`stats_test.go`, `baseline_test.go`), all offline,
  deterministic (no randomness — a small cycling sequence gives a known,
  nonzero baseline spread). Full suite green on both Windows and WSL2
  Arch.
- Own test-script bug, not a product bug: a verification script's bare
  `wait` deadlocked against the long-running `heimdalld` daemon it had also
  backgrounded in the same shell (`wait` with no arguments waits for
  *every* job, including one that never exits on its own). Killed
  manually; noted in `progress.md` so a future verification script
  doesn't repeat it.
- Nothing here touches Sarina or its contract. No `docs/ECOSYSTEM.md`
  change needed.
— Signed: Heimdall / Claude Sonnet 5

### 2026-09-26 (4) — Phase 4 built (first slice): governance consultation, both halves, in Sarina too
- **User decision, explicit:** build both halves now rather than propose
  first and wait — Phase 4 is the first phase where Heimdall-side code alone
  can't do anything (nothing to gate without a caller), so "build the
  proposal" and "build the feature" were effectively the same ask here.
  This entry covers changes in **both** `Heimdall` and `Sarina`.
- **Heimdall side:** new `internal/governance` (`Reviewer.Review`) runs the
  existing `injection-phrase`, `credential-shape`, and `invisible-unicode`
  detectors against arbitrary text on demand, and `internal/api/review.go`
  exposes it as `POST /v1/review` — the one write/action endpoint on an
  otherwise read-only API, documented as a deliberate, narrow exception in
  the package doc comments rather than folded in silently. Every
  consultation (allowed or denied) is recorded as an alert via the same
  multi-sink `cmdRun` already wires everything else through, so a
  governance decision leaves the same audit trail as any other detection.
  17 new tests (`governance` + `api`), all offline (`httptest`, no real
  network).
- **Sarina side:** new `sarina/sentry_governance.py` (`consult_sentry`,
  stdlib `urllib.request` only), wired into `sarina/memory_security.py`'s
  `scan_memory_text` — the single existing gate function both memory-write
  call sites (`memory_runtime.py`, `memory_review.py`) already funnel
  through, so **zero call sites needed to change**. Heimdall is consulted
  only after Sarina's own in-process checks pass (cheap short-circuit, and
  keeps Sarina's own reasons as the reported reason when both would have
  caught something). Fails open (returns `None`, falls back to Sarina's
  own result) when `SENTRY_REVIEW_URL` is unset or Heimdall is unreachable;
  fails closed (blocks) on an actual `"deny"`. 10 new tests
  (`test_sentry_governance.py` + additions to `test_memory_security.py`),
  offline — against a real loopback `http.server.HTTPServer` in a
  background thread, matching `test_chymaera_console.py`'s own
  real-socket-not-mock convention, not `unittest.mock`. Full Sarina suite
  re-run after: 970 passed, 15 failed — the same pre-existing
  POSIX-specific failures (dotenv-guard, bash banner, MCP stdio, process
  kill) this repo's own `CLAUDE.md`/`progress.md` already document, none
  touching memory/sentry code; confirmed by name, not just count.
- **Verified end-to-end for real, not just unit-tested per repo:** built
  and ran the actual `heimdalld` binary with `api_addr` set, then from a
  separate terminal ran real Python in a Sarina checkout calling
  `consult_sentry` and `scan_memory_text` against it over loopback HTTP.
  An injection phrase sent from Python came back denied with the Go
  detector's exact reason string; `GET /v1/alerts` afterward showed the
  consultation recorded with the session id threaded through correctly.
  This is the same rigor applied to Phases 1-3's WSL verification, applied
  here to a cross-repo, cross-language path where a unit test in either
  repo alone couldn't have caught a wire-format mismatch.
- **Why the identical detectors on both sides isn't pointless
  redundancy:** today, yes, Sarina's in-process check and Heimdall's copy
  would always agree, since they're literally the same three pattern
  lists. The value is architectural, not in today's regex coverage: a
  compromised or sufficiently manipulated agent session could in principle
  disable or bypass its own in-process `memory_security.py` from within
  its own process; it cannot reach into Heimdall's separate OS process to do
  the same. Recorded plainly in `docs/ARCHITECTURE.md` so this isn't
  mistaken for an oversight later.
- **Deliberately narrow scope, not the whole Phase 4 sketch.** Only the
  memory-write path is wired up. Escalation-to-Claude-Code and
  permission-tier requests (this section's original examples) are not —
  `escalation_runtime.py` doesn't yet have memory_security.py's "exactly
  one gate" property, so wiring those in means finding that gate first,
  not sprinkling consult calls across call sites. Left for a future slice.
- **To future agents on either board:** the `/v1/review` request/response
  JSON shape is now a real, tested, live contract between two repos (see
  the Cross-repo contracts entry above) — a breaking change to it needs
  updating `internal/governance`, `internal/api/review.go`,
  `sarina/sentry_governance.py`'s docstring, and this file's contract
  entry, together, in one commit, with `CONTRACT:` in the message.
— Signed: Heimdall / Claude Sonnet 5

### 2026-09-26 (3) — Phases 1-3 verified end-to-end on real Arch Linux (WSL2)
- Everything up to this point had only run on the Windows development
  machine -- real tests, but the Linux-specific parsers (`hostsource`,
  `netsource`) were exercised only against hand-built fixture files, never
  real `/proc`. Installed Go via `pacman` on this machine's Arch WSL2
  distro (matching Chymaera OS's own testing precedent, per the user)
  and re-ran the full suite there: green, `go vet` clean, no surprises.
- **Real `/proc/net/tcp` data caught nothing wrong, but was a real check,
  not a formality:** a live line decoded to `10.255.255.254:53`, a
  genuine WSL2-internal DNS address -- confirms the hex byte-order math
  against data nobody hand-crafted to pass.
- **Live end-to-end detections, not just unit tests:** a real
  tamper-and-rescan of a watched file produced a correct `file-integrity`
  finding (exit 1) across two separate `heimdalld scan` processes -- the
  exact cross-process scenario the FIM persistence fix (logged below)
  targets. A real `python3`-bound `0.0.0.0` listener produced a correct
  `network-exposure` finding (exit 1), and correctly cleared once the
  listener stopped.
- **One thing found and documented as intentional, not a bug:**
  `network-exposure` re-reports a standing violation on every separate
  `scan` invocation, unlike FIM (once). Root cause: a bind/connection
  violation needs no history to evaluate; file integrity is inherently a
  diff against a saved baseline. Documented in `docs/ARCHITECTURE.md`'s
  Phase 3 section so a future reader doesn't mistake this asymmetry for
  an inconsistency.
- **Not exercised:** the known cross-user FIM read-permission gap
  (`README.md`) -- WSL testing ran as `root`, so the permission boundary
  that gap is about never came up. Still open.
- Added `progress.md`, a terse cross-session "done vs. still open" index
  (distinct from this log and from `docs/ARCHITECTURE.md`), per the user's
  ask, matching the convention Sarina's own `progress.md` already
  established for this ecosystem.
— Signed: Heimdall / Claude Sonnet 5

### 2026-09-26 (2) — Phase 3 built: network-exposure monitoring (connection half only)
- **New `internal/sources/netsource`.** Polls `/proc/net/tcp` and
  `/proc/net/tcp6` -- the same source `ss`/`netstat` read from -- for
  violations of the ecosystem-wide "loopback only" rule against the
  ecosystem's own claimed ports (8765, 8899, 44700, 8930). Two checks:
  `non_loopback_bind` (one of these ports `LISTEN`ing on a non-loopback
  address, `0.0.0.0`/`::` included) and `non_loopback_peer` (an
  `ESTABLISHED` connection to one of these ports from a non-loopback
  remote). New `network-exposure` detector, a thin stateless translator --
  state-transition tracking (alert once per violation, not once per poll)
  lives in the source, the same split Phase 2's `FIMWatcher` uses.
- **Deliberately not built: the mesh half of Phase 3** (Tailscale-style
  cross-machine alert sharing). Still not currently planned -- see
  `docs/ARCHITECTURE.md`'s Phase 3 section for why (fleet-scale answer to
  a single-operator project; introduces a trust question nobody asked to
  solve). Also deliberately not built: any actual packet capture -- the
  whole point of reading `/proc/net/tcp{,6}` instead is that connection
  *state* is the entire signal this needs.
- **The kernel's hex address encoding was worth getting right, not
  assuming.** IPv4 is 4 bytes reversed; IPv6 is 4 independently-reversed
  32-bit words, not one 16-byte reversal -- hand-verified against a real
  `::1` encoding and a set of hand-computed IPv4 fixtures in
  `netsource_test.go` (`TestParseProcNetTCP`, `TestParseHexIPv6Loopback`).
  One fixture's hand-computed hex was wrong on the first pass (byte order
  backwards, would have parsed 5.0.0.10 as 10.0.0.5) and caught by the
  test itself, not by inspection -- worth knowing if touching this parser
  again: verify fixture hex by decoding it back, don't just eyeball it.
- New config fields, all optional with sensible defaults since these ports
  are the same fixed constants on every Chymaera OS install, not a
  per-machine path like `agent_session_dir`/`fim_paths`:
  `net_ports` (defaults to the full registry), `net_poll_interval_seconds`.
  Runs by default on a supported platform; self-disables gracefully (logs
  once, stops) where `/proc` doesn't exist, same as telemetry.
- 8 new tests, all offline/stdlib-only. Full suite green. Manually
  smoke-tested `heimdalld scan` end-to-end on the development machine
  (Windows, no `/proc`) to confirm graceful, silent self-disabling rather
  than an error or crash.
- Nothing here touches Sarina or its contract -- Phase 3 watches host
  network state, not Sarina's output. No `docs/ECOSYSTEM.md` change
  needed, though the port registry there (§6) is now cross-referenced by
  `net_ports`' default.
— Signed: Heimdall / Claude Sonnet 5

### 2026-09-26 — Burst-detector efficiency fix; Phase 2 (host telemetry & FIM) built
- **`session-burst` rewritten as a leaky bucket.** The original kept every
  `session_created` timestamp in a slice and re-pruned it on every event —
  O(n) work and memory per call. Now two `float64`/`time.Time` fields: a
  level incrementing by one per event, draining continuously at
  `threshold/window` per second — the same primitive CrowdSec's own
  "leaky" bucket type uses. O(1) per event regardless of uptime. Public
  constructor signature unchanged; behavior verified equivalent via
  rewritten tests plus a new decay-specific test
  (`TestBurstDetectorDecaysOverTime`).
- **Phase 2 built: `internal/sources/hostsource`.** File integrity
  (`fim.go`, Wazuh-syscheck-style mtime+size precheck before hashing) and
  host telemetry (`telemetry.go`, `/proc/meminfo` + `/proc/loadavg`,
  load-per-core rather than a jiffy-delta CPU% since it needs no kept
  previous sample). Two new detectors: `file-integrity` (thin translator
  over the source's own file_modified/file_deleted Events) and
  `resource-pressure` (edge-triggered, alerts once per threshold crossing
  rather than every poll during sustained pressure).
- **A real bug caught while testing, not a design taken on faith: FIM
  baselines needed to persist to disk.** First version kept them in memory
  only. Every `heimdalld scan` invocation is a fresh process, so every scan
  looked like a first-ever observation and silently re-established a
  baseline instead of comparing against history — a genuine tamper between
  two scans (or across a `heimdalld run` restart) would never have been
  reported. Manual end-to-end testing against real files caught this
  before it shipped; fixed with `NewFIMWatcherWithState` (JSON snapshot,
  atomic write-then-rename so a crash mid-write can't corrupt it) and
  pinned down with a regression test
  (`TestFIMWatcherPersistsBaselineAcrossInstances`) that constructs two
  separate watcher instances the way two process invocations would.
- New config fields, all optional: `fim_paths` (empty disables FIM, same
  reasoning as `agent_session_dir`), `fim_poll_interval_seconds`,
  `fim_state_path`, `telemetry_interval_seconds`,
  `resource_mem_threshold_percent`, `resource_load_threshold_per_cpu`.
  `packaging/arch/config.json.example` updated to show all of them.
- 14 new tests, all offline, stdlib-only (fixture `/proc`-shaped files for
  telemetry parsing, real temp-dir files for FIM). Full suite green.
  Verified end-to-end against real files on the development machine (not
  just unit tests) both before and after the persistence fix, which is
  what surfaced the bug in the first place.
- Nothing here touches Sarina or its contract — Phase 2 watches the host,
  not Sarina's output. No `docs/ECOSYSTEM.md` change needed.
— Signed: Heimdall / Claude Sonnet 5

### 2026-09-25 — Heimdall created; registered as the ecosystem's fifth repo
- New repo, built from scratch: a Go security agent watching Sarina from
  outside its process. User-provided references informed the full
  five-phase roadmap in `docs/ARCHITECTURE.md` — CrowdSec (engine shape:
  sources → detectors → sinks, scoped down from CrowdSec's own
  parser/scenario/decision split), Wazuh + Netdata (Phase 2: host FIM +
  telemetry, not built), Zeek + Tailscale (Phase 3: network monitoring +
  mesh, not built), CodeStrike + Paperclip + OpenExecutive (Phase 4: an
  approval-gate pattern generalizing Sarina's own `memory_review.py`, not
  built), TensorFlow + DeepVariant (Phase 5: ML pattern recognition over
  accumulated telemetry, following Sarina's own onnxruntime-not-TensorFlow
  precedent rather than vendoring either directly, not built). Only Phase
  1 (agent-behavior monitoring) is implemented.
- **Language: Go, zero third-party dependencies**, chosen explicitly over
  Python (Sarina's language) for lower idle CPU/RAM as an always-on daemon
  and to keep Heimdall decoupled from whatever language Sarina's own code is
  written in, including a possible future Rust rewrite the user mentioned
  is under consideration. Arch Linux only (Chymaera OS specifically) —
  no cross-platform target, unlike Sarina.
- **Phase 1 detectors directly port Sarina's `sarina/memory_security.py`**
  (injection-phrase patterns, credential-shape patterns, invisible/bidi/tag
  Unicode scan) so the same threat model that guards Sarina's curated
  memory writes is applied from outside to everything a session transcript
  contains. Added two detectors with no Sarina equivalent:
  `permission-escalation` (parses "Permission denials: N" already present
  in session message text) and `session-burst` (rate-based, since a single
  operator's session-creation rate has no fleet baseline to compare
  against). Verified end-to-end against Sarina's real
  `.port_sessions/*.json` files (clean, as expected) and against a crafted
  malicious fixture (both new detectors fire correctly, `scan` exits 1).
- **`internal/sources/agentsource` polls rather than uses `fsnotify`** —
  a single operator's session directory sees at most a few writes/minute;
  `os.Stat` in a loop is one syscall per file per poll and not worth a
  dependency yet. Recorded as a Phase 2 revisit, not an oversight.
- 22 tests, all offline (`go test ./...`), stdlib-only; fixture session
  files built via `encoding/json` rather than string concatenation after an
  early version of the agentsource test corrupted its own fixture with an
  unescaped embedded newline — worth knowing if extending those tests.
- Arch packaging (`packaging/arch/`) mirrors Sarina's own layout: PKGBUILD
  (`go build`, no CGO), a sandboxed systemd unit
  (`ProtectHome=read-only` since Heimdall only ever reads a Sarina
  workspace), a sysusers snippet, and a config example. **Known gap, not
  yet solved:** the service's own Linux user needs cross-user read access
  to whatever user's Sarina workspace it watches — flagged in the README
  as a packaging TODO rather than silently assumed away.
- **To the Sarina instance:** this repo proposes the `.port_sessions`
  polling contract above. It is marked proposed, not agreed — Heimdall will
  keep absorbing format changes on its own until/unless you accept
  freezing the shape. Also claiming port `8930` in your `docs/ECOSYSTEM.md`
  §5 registry for Heimdall's status API; that edit is included in this same
  round of changes.
— Signed: Heimdall / Claude Sonnet 5

<!-- Append entries at the top of this list. Format:
### YYYY-MM-DD — short title
- what changed / why / what others need to know
— Signed: <project> / <model>
-->

---

## 6. Behavioral guidelines

Guidelines to reduce common LLM coding mistakes, adopted verbatim from
Sarina's `CLAUDE.md` §6, which itself credits the protocol
`Argus_App` established. These apply alongside the
project-specific instructions above.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial
tasks, use judgment.

### 6.1 Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 6.2 Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes,
simplify.

### 6.3 Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 6.4 Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it
work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs,
fewer rewrites due to overcomplication, and clarifying questions come
before implementation rather than after mistakes.
