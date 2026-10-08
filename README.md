# Heimdall

A security agent for [Sarina](https://github.com/Artifex-Technologies/Sarina) — the
local-model AI coding agent shipped in Chymaera OS. Heimdall watches
Sarina from outside its process, looking for prompt injection, leaked
credentials, invisible-Unicode smuggling, permission escalation, and
abnormal session-creation bursts, and raises alerts a human or another tool
can act on.

Heimdall is the fifth repo in the Chymaera Ecosystem — see
[Sarina's `docs/ECOSYSTEM.md`](https://github.com/Artifex-Technologies/Sarina/blob/main/docs/ECOSYSTEM.md)
for the full four-repo contract this one now joins, and this repo's
[`CLAUDE.md`](CLAUDE.md) for Heimdall's own coordination board.

## Why a separate process, and why Go

A security monitor that shares a runtime, a dependency tree, or a crash
with the thing it watches is a weaker monitor. Heimdall runs as its own
binary and talks to Sarina only through what Sarina already writes to disk
(session files today; see the roadmap below for what's next) — no shared
memory, no importing Sarina's code, no coupling to whatever language
Sarina's own code is written in.

Go, specifically, for the same reason [CrowdSec](https://github.com/crowdsecurity/crowdsec)
and [Tailscale](https://github.com/tailscale/tailscale) are Go: a single
static binary, no interpreter/GC-heavy runtime idling between the monitor
and the host, low CPU/RAM for something meant to run forever in the
background. **The whole binary has zero third-party dependencies** — see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for why that's a deliberate
choice, not an accident of the current feature set.

**Arch Linux only.** This targets Chymaera OS specifically, not
"Linux and best-effort elsewhere" — see `docs/ARCHITECTURE.md`'s "Arch,
specifically" section.

## What's built vs. planned

**Phase 1 (agent-behavior monitoring), Phase 2 (host telemetry & file
integrity), the connection-monitoring half of Phase 3 (network exposure),
a first slice of Phase 4 (governance), and a first slice of Phase 5 (a
statistical baseline over host telemetry) are built.** The rest of the
five-phase roadmap — the network mesh, the rest of governance, and the
rest of pattern recognition, each grounded in a specific reference project
— is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Read it before
starting any later phase, and see
[`docs/REFERENCES.md`](docs/REFERENCES.md) for the tracked ledger of every
external project cited anywhere in this repo — what it's for, what (if
anything) got adapted from it, and where to look if it updates.

### Phase 1 detectors — agent behavior

| Detector | Catches |
| --- | --- |
| `injection-phrase` | Text reading as an instruction override ("ignore all previous instructions", "you are now...") |
| `credential-shape` | Private keys, cloud/API tokens, password-looking assignments |
| `invisible-unicode` | Zero-width/bidi-override/tag Unicode characters hiding instructions from a human skim |
| `permission-escalation` | A session reporting one or more permission denials |
| `session-burst` | An abnormally high rate of new sessions (leaky-bucket rate limiter, CrowdSec-style) |

The injection/credential/invisible-unicode patterns are ported from
Sarina's own `sarina/memory_security.py` — the same threat model Sarina
applies to its curated-memory writes, applied here from outside to
everything a session transcript contains.

### Phase 2 detectors — host

| Detector | Catches |
| --- | --- |
| `file-integrity` | A watched file (`fim_paths`) changed or was deleted — cheap mtime+size precheck before hashing, Wazuh-syscheck-style; baselines persist to disk so a restart or a one-shot `scan` doesn't silently reset them |
| `resource-pressure` | Host memory or load average crossed a threshold (edge-triggered, alerts once per crossing) |

Neither Phase 2 source is enabled unless configured: `fim_paths` must be
set for file integrity, though host telemetry runs by default on a
supported platform (self-disables gracefully where `/proc` doesn't exist).

### Phase 3 detector — network exposure

| Detector | Catches |
| --- | --- |
| `network-exposure` | An ecosystem port (`net_ports`, defaults to the registry: 8765, 8899, 44700, 8930) is bound or connected from somewhere other than loopback |

Reads `/proc/net/tcp{,6}` connection state — the same source `ss`/`netstat`
read from — not packet capture. Runs by default on a supported platform,
same self-disabling behavior as telemetry.

### Phase 4 — governance (first slice: memory writes)

`POST /v1/review` runs Heimdall's own copy of the `injection-phrase`,
`credential-shape`, and `invisible-unicode` detectors against text a
sibling process is about to persist, and returns `{"decision":
"allow"|"deny", "reasons": [...]}`. Sarina's `sarina/memory_security.py`
consults it (opt-in via `SENTRY_REVIEW_URL`) after its own in-process
checks pass, folding a deny into the same result its own checks already
produce. Every consultation is logged as an alert regardless of outcome.
Fails open if Heimdall isn't configured or isn't reachable; an actual `deny`
is respected, not merely logged. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)'s Phase 4 section for why
running this in a separate process is the actual point, not a formality.

### Phase 5 detector — baseline drift

| Detector | Catches |
| --- | --- |
| `baseline-drift` | A `host_telemetry` value (`mem_percent`, `load_per_cpu`) that's a statistical outlier against *this host's own* learned normal range — not a fixed percentage, a learned one (`baseline_z_threshold` standard deviations, default 3.0, after `baseline_min_samples` observations, default 20) |

Runs on the same telemetry Phase 2 already collects — no new source. This
is honest streaming statistics (Welford's algorithm, `internal/detect/stats.go`),
not a model — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)'s Phase 5
section for why that's a deliberate, accurately-described scope rather
than an overclaimed "ML" feature.

## Quick start

Requires Go 1.21+ to build; the built binary has no runtime dependencies.

```bash
go build -o heimdalld ./cmd/heimdalld
```

Write a config pointing at a Sarina workspace's session directory:

```json
{
  "agent_session_dir": "/path/to/Sarina/.port_sessions",
  "alert_log_path": "/var/lib/heimdall/alerts.jsonl",
  "api_addr": "127.0.0.1:8930"
}
```

Every field is optional except `agent_session_dir`; see
[`internal/config/config.go`](internal/config/config.go) for defaults.

```bash
./heimdalld scan --config config.json   # one-shot: print findings, exit 1 if any
./heimdalld run  --config config.json   # foreground daemon, polls until killed
./heimdalld version
```

`scan` is the one to run by hand or from cron/CI — it prints one JSON alert
per line and exits non-zero on any finding, the same convention Sarina's
own `desktop-audit` uses. `run` is what the systemd unit below starts.

### Status & governance API

When `api_addr` is set, `run` serves a **loopback-only** HTTP API.
`/healthz` and `/v1/alerts` are read-only; `/v1/review` is the one
exception — a sibling process's behavior may depend on its response:

| Endpoint | Description |
| --- | --- |
| `GET /healthz` | liveness check |
| `GET /v1/alerts?n=50` | the `n` most recent alerts, newest first (default 50, max 500) |
| `POST /v1/review` | `{"kind","session_id","text"}` → `{"decision":"allow"\|"deny","reasons":[...]}` — see Phase 4 above |

## Arch Linux packaging

`packaging/arch/` mirrors Sarina's own `packaging/arch/` layout: a
`PKGBUILD` (builds via `go build`, no CGO), a systemd unit (sandboxed —
`ProtectSystem=strict`, `ProtectHome=read-only` since Heimdall only ever
reads a Sarina workspace, never writes to it), a `sysusers.d` snippet for
the unprivileged service user, and a config example.

```bash
cd packaging/arch
makepkg -si
sudo systemctl enable --now heimdall
```

**Cross-user read access.** The systemd unit runs as its own
`heimdall` user, which needs read access to whatever user's Sarina
workspace it's pointed at — grant it via a shared group on the
`.port_sessions` directory (or its parent) rather than widening the
service's sandbox. Not yet automated; a packaging TODO once there's a real
multi-user deployment to design against.

## Testing

```bash
go test ./...
go vet ./...
```

Every test is offline and stdlib-only — no Sarina process, no model
backend, no network. `internal/sources/agentsource`'s tests build fixture
session files with the exact schema a real Sarina `.port_sessions/*.json`
file has (verified against a live Sarina checkout while building this).

## Disclaimer

Heimdall reads Sarina's on-disk session files and, when `api_addr` is
configured, answers governance consultations Sarina's own code may send it
(Phase 4, opt-in via `SENTRY_REVIEW_URL` on Sarina's side). Neither
direction imports the other's code — Heimdall doesn't import Sarina's
Python, and Sarina's `sentry_governance.py` only ever speaks HTTP to it.
Heimdall is not maintained by the Sarina project, and both the session-file
shape it reads and the `/v1/review` contract are recorded as **proposed,
not yet frozen**, in this repo's `CLAUDE.md` Coordination Log — see there
before relying on either staying exactly this shape.

## License

MIT. See [`LICENSE`](LICENSE).
