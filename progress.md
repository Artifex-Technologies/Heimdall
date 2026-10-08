# Progress Log

Running log of multi-session build work, so a new chat can pick up without
re-deriving context. Distinct from the other two tracking documents in this
repo, which serve different purposes:

- **`CLAUDE.md`'s Coordination Log** is the cross-repo message board --
  dated entries other Chymaera Ecosystem repos' agents may read, signed per
  entry, focused on contracts and what siblings need to know.
- **`docs/ARCHITECTURE.md`** is the design reference -- the 5-phase roadmap
  and why each phase is shaped the way it is. It doesn't change often and
  doesn't track session-to-session state.
- **This file** is neither: a terse, current "what's actually done vs.
  still open" index for whoever (human or agent) picks this repo up next,
  in this repo or a sibling's.

Append new entries at the top. When a thread closes out completely, mark it
closed rather than deleting it -- the history of *why* is worth keeping.

---

## 2026-09-26 — Building the 5-phase roadmap (IN PROGRESS)

**Ask:** build `docs/ARCHITECTURE.md`'s five-phase roadmap incrementally,
phase by phase, stdlib-only Go, each phase usable and tested before moving
to the next -- not a big-bang design-then-implement pass.

### Done

1. **Repo scaffold + Phase 1 (agent-behavior monitoring).** Watches a
   Sarina `.port_sessions/` directory. Five detectors: `injection-phrase`,
   `credential-shape`, `invisible-unicode` (all ported from Sarina's own
   `sarina/memory_security.py`), `permission-escalation`, `session-burst`.
   Registered as the ecosystem's 5th repo (Sarina's `docs/ECOSYSTEM.md` +
   `CLAUDE.md` updated, contract marked **proposed**).
2. **Burst-detector efficiency fix.** `session-burst` rewritten from an
   O(n) timestamp-slice-prune to a CrowdSec-style O(1) leaky bucket.
3. **Phase 2 (host telemetry & file integrity).** `internal/sources/hostsource`:
   FIM against an explicit path list (Wazuh-syscheck-style mtime+size
   precheck before hashing, baselines persisted to disk -- a real bug
   caught in testing, see `CLAUDE.md`'s log for 2026-09-26), plus
   `/proc/meminfo` + `/proc/loadavg` telemetry (load-per-core, not a
   jiffy-delta CPU%). New `file-integrity` and `resource-pressure`
   detectors.
4. **Phase 3, connection-monitoring half (network exposure).**
   `internal/sources/netsource` polls `/proc/net/tcp{,6}` for the
   ecosystem's claimed ports (8765, 8899, 44700, 8930) bound or connected
   from somewhere other than loopback. New `network-exposure` detector.
5. **Verified end-to-end on real Arch Linux (WSL2), not just fixtures.**
   Installed Go via `pacman`, built and ran the real suite there: all
   tests green, `go vet` clean. Then live-tested against real state,
   catching two things fixture-only testing couldn't have:
   - Real `/proc/net/tcp` data on this machine (`FEFFFF0A:0035` ->
     `10.255.255.254:53`, a genuine WSL2 internal DNS address) confirmed
     the hex address byte-order math against something nobody hand-wrote
     for a test.
   - A real tamper-and-rescan of a watched file correctly produced a
     `file-integrity` finding with exit code 1 across two separate
     `heimdalld scan` processes (the exact scenario the FIM persistence fix
     targets), and a real `python3`-bound `0.0.0.0` listener on a test
     port correctly produced a `network-exposure` finding, also exit 1,
     and correctly cleared once the listener stopped.
   - **Found and documented, not a bug:** `network-exposure` re-reports a
     standing violation on every separate `scan` invocation, unlike FIM,
     which reports once. This is because a bind/connection violation
     needs no history to evaluate ("is this true right now"), while file
     integrity is inherently a diff against a saved baseline. Recorded in
     `docs/ARCHITECTURE.md`'s Phase 3 section so it doesn't read as an
     inconsistency later.
6. **Phase 4, first slice (governance): both halves, in both repos.**
   User's explicit call -- build the real thing, not a proposal, since
   Heimdall alone has nothing to gate. New `internal/governance` +
   `POST /v1/review` in this repo; new `sarina/sentry_governance.py` in
   **Sarina**, wired into `sarina/memory_security.py`'s single existing
   gate function (`scan_memory_text`) so zero Sarina call sites needed to
   change. Fails open on Heimdall's absence/unreachability, fails closed on
   an actual deny. Scope is deliberately narrow: only the memory-write
   path, not escalation or permission requests (see `docs/ARCHITECTURE.md`).
   **Verified for real, cross-repo, cross-language:** a live `heimdalld run`
   process, and real Python in a Sarina checkout calling it over loopback
   HTTP -- an injection phrase came back denied with the exact Go detector
   reason string, and showed up in `/v1/alerts` with the session id
   threaded through. Full detail in both repos' 2026-09-26 Coordination
   Log entries (this repo's dated "(4)"; Sarina's own board has the
   matching entry).
7. **`docs/REFERENCES.md` added** -- a flat, trackable ledger of every
   external reference project cited anywhere in this repo (16 total),
   with a status per row (Adapted / Design reference / Candidate /
   Methodology-only), what file the adaptation actually lives in, and a
   **Checked** date so a future update to any of them has something
   concrete to diff against instead of a re-read of the whole roadmap.
   User supplied an updated, larger reference list (adding n8n, GraphRAG,
   Letta, TALON, headscale, ONNX to the original ten); three of the six
   new ones were verified by fetching the actual repo before writing
   anything about them (same discipline that caught the CodeStrike
   mischaracterization earlier) rather than assumed from the name.
   **One real finding from that pass: `juanfont/headscale` reopens Phase
   3's mesh half.** That section was marked "not currently planned"
   specifically because a shared CrowdSec-style central API raises a
   trust question (whose server, what data leaves the machine) this
   project was never asked to solve. Headscale is a self-hosted
   implementation of Tailscale's own control server -- same mesh
   mechanics, but self-hosted answers exactly that objection. Doesn't
   move the mesh to *built*; recorded so the next time it comes up gets a
   real design pass instead of the same reflexive "not planned."
8. **Phase 5, first slice: `baseline-drift` detector.** Online mean/
   variance via Welford's algorithm (`internal/detect/stats.go`, O(1)
   memory/work, no history array) applied to the same `host_telemetry`
   Fields (`mem_percent`, `load_per_cpu`) Phase 2 already collects -- no
   new source. Flags a value more than `baseline_z_threshold` (default
   3.0) standard deviations from the *learned* mean, after
   `baseline_min_samples` (default 20) observations; edge-triggered, same
   convention as `resource-pressure`. Deliberately described as honest
   streaming statistics, not "ML" -- see `docs/ARCHITECTURE.md`'s Phase 5
   section for why that framing matters and how it maps to TALON's
   known-vs-novel classification idea from the new reference list.
   **Verified live on real Arch Linux (WSL2) with a genuine CPU load
   spike** (`yes > /dev/null` busy loops), not a synthetic unit-test
   fixture: both `load_per_cpu` and `mem_percent` correctly fired.
   **Real calibration finding, not a bug:** on this near-idle host the
   natural baseline variance was tiny (stddev 0.01-0.02), so small
   absolute changes (load 0.00→0.02, memory 18.14%→18.28%) registered as
   3.6 and 5.9 standard deviations respectively -- correct behavior for a
   z-score detector on a low-variance signal, but worth knowing before
   assuming the default threshold suits every host. Documented plainly
   rather than tuned away, since it's genuinely how the technique behaves.
   Own test-script bug caught and fixed along the way: a verification
   script used bare `wait` with the long-running `heimdalld` daemon also
   backgrounded in the same shell, which waits for *every* backgrounded
   job including one that never exits on its own -- deadlocked the
   script, not the product; killed manually and noted here so a future
   verification script doesn't repeat it.

Each step above: built, unit-tested (stdlib-only, offline), `go vet`
clean, manually smoke-tested against real or fixture data before moving
on. Full detail and dates are in `CLAUDE.md`'s Coordination Log; this list
is deliberately shorter.

### Still to do

- **Phase 3, mesh half.** Tailscale-style cross-machine alert sharing.
  No longer blocked by the same trust objection (see `headscale` above),
  but no design work has started -- still not built.
- **Phase 4, the rest of it.** Escalation-to-Claude-Code and
  permission-tier requests were the other two examples in the original
  Phase 4 sketch; neither is wired up. `escalation_runtime.py` doesn't yet
  have `memory_security.py`'s "exactly one gate" property, so that's a
  prerequisite before extending governance there, not a drop-in.
- **Phase 5, the rest of it.** Cross-alert graph correlation
  (microsoft/graphrag's transferable idea) and applying the same
  baseline technique to agent-behavior signals, not just host telemetry,
  are both sketched in `docs/ARCHITECTURE.md` but not started.
- **`baseline_z_threshold`'s default may want revisiting** per the live
  finding above -- 3.0 is the conventional starting point, not something
  tuned against this project's actual telemetry yet.
- **Known packaging gap:** the systemd service's own Linux user needs
  cross-user read access to whatever user's Sarina workspace it watches.
  Flagged in `README.md`, not yet solved. Not exercised by the WSL testing
  above (that ran as `root`, so the cross-user permission boundary this
  gap is actually about never came up) -- still open.
- **Phase 4's `/v1/review` has no auth beyond loopback-only binding.**
  Consistent with `/v1/alerts` having none either, but worth a second
  look if this ever needs to run somewhere loopback isn't a strong enough
  boundary (e.g. a shared multi-tenant host).
