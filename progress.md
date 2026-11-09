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

## 2026-11-09 — Running light, phase 0 of the Rust port (DONE in code; install is mine)

**My ask:** make heimdalld much cheaper to run (I game and run a local model at the same time), from the measurement study's
findings, with tests and a side-by-side proof. The design carries into the Rust port (`docs/ARCHITECTURE.md`, "Running light").

| Item | State | Commit | Tested / measured |
| --- | --- | --- | --- |
| IP databases mapped, not read into the heap | done | `f8ea8e2` | same answers and errors as before; a file cut short under the mapping is an error, not a crash; old mapping released after an update |
| Text detectors: case-folded once, literal prefilter | done | `8b46c76` | differential test, old vs new on ~53,000 texts: identical; 29-37x less work on ordinary text |
| Sessions by inotify, full look every 10 min, state written only on change | done | `2bf2ef1` | settle window, permissions fixed, folder gone and back; 15.9 ms every 5 s -> 11.4 ms every 10 min |
| One shared /proc/net/tcp read; socket owners looked for once | done | `783c3a6` | churn test equal to a walk every look; 5.7 ms -> 4.6 us a look with nothing new |
| One journalctl --follow with a cursor | done | `d556cb9` | fake journalctl: restart after the last entry, cursor kept; 0.028 % -> 0.009 % of a core |
| Long audits wait while a game runs | done | `685c2dd` | fake game-time tool; missing tool runs as before |
| CPUWeight/IOWeight/Nice in the units | done | `be29415` | systemd-analyze verify; heimdall-contain left at full priority on purpose |

- Side by side, old and new heimdalld on the same synthetic load (table in `docs/ARCHITECTURE.md`): idle CPU 0.579 % ->
  0.046 % of a core, context switches 10.2/s -> 2.1/s, PSS 118.7 -> 23.5 MB. With activity and planted events (injection,
  key, zero-width space, password, Limbo guest without policy, FIM change, vault note, port off loopback, new listener):
  0.538 % -> 0.075 %, 12.2/s -> 5.3/s, 120.3 -> 24.7 MB. Alerts: 77 and 77, identical once the time is dropped.
- How the run was made (so the Rust port can repeat it): both daemons and a load generator in one `unshare -rn` network
  namespace with a dummy interface (203.0.113.1, 198.51.100.1), so only made-up connections are seen; 6,629 session files,
  25 FIM files, 40 MB of generated MaxMind-format databases; host-load alerts switched off by config in both; 240 s after a
  45 s warm-up at nice 15; CPU from /proc/PID/stat, context switches summed over /proc/PID/task, PSS from smaps_rollup;
  alerts.jsonl compared as multisets with `time` dropped. The scripts stayed outside the repo.
- **Open:** install and restart (owner steps in the Coordination Log entry of 2026-11-09); the live numbers on my PC after that.

## 2026-11-05 (2) — Limbo's new network and exchange events (DONE; one proposal waited for my answer, approved 2026-11-05)

**Ask:** act on the events Limbo started writing today (`net.*`, `exchange.*`).

| Item | State | Commit | Tested |
| --- | --- | --- | --- |
| `net.anomaly` -> `limbo-network` alert (host/LAN probe critical, scan/ipv6 warning), `net.capped` info | done | `f84191c` | table tests; scan of a sample log |
| host_probe / lan_probe / scan restrict the guest (restrict level, only with auto-quarantine on) | done | `f84191c` | fake Limbo in tests; `heimdalld run` against a fake control.sock: one restrict call for lan_probe, none for ipv6 |
| Incidents: network + exchange alerts for one guest link | done | `f84191c` | correlator test; the guest's path does not link to a host file |
| `exchange.held` -> warning, `exchange.fail` -> info | done | `f84191c` | table tests |
| Copy a held file into immunity | done by hand (`immunity take-limbo`); automatic is a proposal | `d8561df` | unit tests (refusals: bad name, wrong hash, link, missing); real ClamAV on EICAR |
| `ask_password=true` was a critical "credential" | fixed | `d2a39d4` | verify tests; scan of the sample log |

- `net.flow` and `net.blocked` are deliberately not alerts (normal traffic; Limbo already turns refusals into anomalies).
- No new polling or timers: the detectors keep no state, Limbo bounds how often it writes each event.
- The live config has `limbo_auto_quarantine: true`, so after the install a probing guest will be restricted.
- **Was open:** my answers (automatic take of held files; whether a held file should also restrict its guest): both yes,
  built 2026-11-07 in `0f80ee0`. **Still open:** install from the newest commit (owner steps, section 6).

## 2026-11-05 — The pending list, closed (DONE except what needs me or the second PC)

**My ask:** "complete the pending tasks for Heimdall". The 2026-09-26 list below named Python files that no longer exist
(the project is Go, and so is Sarina's core); each item was checked against today's code first.

| Item | State | Commit | Tested |
| --- | --- | --- | --- |
| Packaging: heimdall's account reads Sarina's sessions | done | `4be493b` | tmpfiles file on a throw-away root (ACL, new 0640 file r-- for heimdall, missing folder not an error) |
| API auth beyond loopback | done | `e566b9b` | fixture + real loopback socket; policy table. No client changed |
| Sarina eval vault-note-injection | partly: Heimdall side done | `e1c9896` | inotify live, restarts, links refused. The eval vault is in /tmp, hidden from the service: proposal on Sarina's board |
| Phase 4: one gate, escalations, access tiers | done (off until I switch it on) | `c982b37`, Sarina `123453e` | guard, scope, API; Sarina: auto claude-CLI hand-off refused without approval, runs with it; tier cap |
| Phase 5: incidents, agent baselines, z threshold | done | `c47ba1f` | replay of 5067 real sessions; journal history; numbers in ARCHITECTURE.md; z stays 3.0 |
| Phase 3 mesh | done; second-PC test open | `564bbbe` | two live instances on this PC; checklist in docs/MESH.md |
| YARA rules from Limbo analyses | done (Heimdall side) | `b055be9` | real ClamAV: matches the sample, none of /usr/bin; CLI end to end |

- **What vault-note-injection really measured.** In every failing run since 11-04 the planted line never reached Sarina's
  session (she only searched, her read used a wrong path, or the session ended early); whenever she read the note, Heimdall
  alerted within 5 s. Heimdall now also watches vault notes at rest (`vault_dirs`), which catches the note before any read.
- **Idle cost of the new parts.** Vault watch, mesh listener and senders, correlator, grant and rule endpoints: nothing runs
  without an event (inotify, channel waits, sink wrappers). Two live instances with the mesh on: 0 CPU ticks in 48 s, 18-20 MB.
  The API check costs one read of /proc/net/tcp per request.
- **Owner steps and questions:** `docs/OWNER_STEPS_2026-11-05.md` (install r60, enable the ACL path unit, restart; vault watch;
  grant gate; mesh later). Package `heimdall-git-0.1.0.r60.gb055be9` built in Labyrinth's pkgbuilds folder, not installed.
- **Still open:** the second-PC mesh test (mine); Sarina's eval change and a Sarina tool to send YARA drafts (I said yes; the tool is built, Sarina `d225526`);
  Sarina's `TestToolDefinitionFootprint` fails at her HEAD without this work (her board has it).

## 2026-09-26 — Building the 5-phase roadmap (CLOSED 2026-11-05: every item below is done, see the entry above)

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

### Still to do (as written on 2026-09-26; each closed 2026-11-05)

- ~~Phase 3, mesh half~~ CLOSED: `internal/mesh`, docs/MESH.md (`564bbbe`).
- ~~Phase 4, the rest of it~~ CLOSED: the grant gate (`c982b37`, Sarina `123453e`). The "exactly one gate" prerequisite
  was met by Sarina's Go core (tiers.Router.attempt, config.AccessTierFromEnv), not by escalation_runtime.py, which is gone.
- ~~Phase 5, the rest of it~~ CLOSED: incidents and the agent baseline (`c47ba1f`).
- ~~baseline_z_threshold's default may want revisiting~~ CLOSED: measured on real data; stays 3.0 (the floors decide).
- ~~Known packaging gap: cross-user read access~~ CLOSED: tmpfiles ACL + path unit (`4be493b`).
- ~~/v1/review has no auth beyond loopback~~ CLOSED: callers identified by the kernel (`e566b9b`).
