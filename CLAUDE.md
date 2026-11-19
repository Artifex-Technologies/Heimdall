# CLAUDE.md — Heimdall

Guidance for Claude Code (and any AI agent) working in this repository. Read it top to bottom before making changes.

## 1. What this is

Heimdall is the security agent of the Artifex Ecosystem: a daemon (`heimdalld`) that watches Sarina's output from outside
its process (prompt injection, leaked credentials, invisible-Unicode smuggling, permission escalation, bursts), the host
(file integrity, packages, hardening, network, remote-access tools, Wi-Fi), Limbo's guests, and the files I add (the privacy
pack). It owns the shared security of Labyrinth OS and LykanOS. Since 2026-11-19 the daemon and every command is Rust
(`rust/heimdall`, installed as `/usr/bin/heimdalld`); the Go sources (`cmd/`, `internal/`) are the reference the parity
fixtures are written from. Arch Linux only (`docs/ARCHITECTURE.md`, "Arch, specifically"). Design:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the port: [docs/RUST_PORT.md](docs/RUST_PORT.md), [docs/RUST_CLI.md](docs/RUST_CLI.md).

## 2. Build and test

Always memory-capped and at low priority (games and the local model run on this computer):

```bash
cd rust
systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=4 \
  scripts/nicecargo.sh test --offline          # everything: the Go fixtures, the side-by-side runs, fake roots, namespaces
systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=4 \
  scripts/nicecargo.sh build --release --locked   # target/release/heimdalld-rs, installed as /usr/bin/heimdalld
cargo fmt --all --check && scripts/nicecargo.sh clippy --locked --all-targets -- -D warnings
cd .. && go vet ./... && go test ./...            # the Go reference (stdlib only)
go test ./internal/parity -update                 # rewrite testdata/parity after a change in both languages; review the diff
python3 -m unittest discover -s packaging/tests -p 'test_*.py'   # the packaging and Python helpers' tests
```

`scripts/nicecargo.sh` runs cargo at nice 15. `tests/mesh.rs` needs Go on the PATH for its Go node and says so when it
skips. `rust/yara-check` is a workspace of its own (`cargo test --release` there).

CI (`.github/workflows/rust.yml`, on pushes that touch `rust/`, `internal/`, `testdata/`, `cmd/`, `packaging/`, `VERSION`,
`*.go`): gofmt, the Go fixtures current, `cargo fmt`, clippy `-D warnings`, `cargo test`, the rogue-router namespace test,
the packaging tests, the engine differential; `cli_shtools` in an Arch container; the YARA-X checker; `cargo audit` of both
lock files (weekly too). Watch a push by its full SHA: `gh run list --commit <sha>`.

Running it: `heimdalld scan --config config.json` (one shot, non-zero on any finding), `heimdalld run --config config.json`
(the daemon). `agent_session_dir` has no default; see `packaging/arch/config.json.example`.

## 3. Rules

- **Privacy.** Never write a host name, network address, SSID, BSSID, MAC address, serial or the owner's name into a commit,
  code, test or doc; check the diff before pushing. Never commit real session or alert data (an `alerts.jsonl` holds exactly
  the credentials and injections it exists to catch), tokens or keys.
- **Push as you go.** Push every commit as you make it; don't ask first. Other sessions work in sibling repositories: stage
  by explicit path, `git pull --rebase` before pushing.
- **Heimdall owns the shared security** of Labyrinth OS and LykanOS: security and network features go here, not into the
  distros. `packaging/install.sh` is the one file list: every recipe (packaging/arch, Labyrinth's and LykanOS's
  heimdall-git, the private-mic, multilink and yara-check packages) calls it with its `DESTDIR` and package name.
- **Dependencies.** The Go module is stdlib only. The Rust crates I approved (2026-11-10: regex, serde, serde_json, memmap2,
  rustix, sha2 or ring, ed25519-dalek, rustls, others where needed) are pinned to exact versions, `cargo audit` in CI,
  threads and no async. `yara-x` (2026-11-18) is a dependency of `rust/yara-check` only, never of the daemon.
- **Go and Rust raise the same alerts** while the Go sources are the parity reference: a change to a detector, the
  verifier, the explanations or the engine is made in both, the fixtures rewritten (`go test ./internal/parity -update`)
  and the Rust tests pass on them.
- **Loopback only.** Network-facing features bind loopback by default (`api.rs`; Go's `ListenAndServeLoopback`). The mesh
  is the one non-loopback listener, off by default, on an address I choose.
- **Read-only toward Sarina.** Heimdall never writes into a Sarina workspace and never imports Sarina's code. The deliberate
  exceptions are listed in docs/CONTRACTS.md: answering `POST /v1/review`, the grant gate (Sarina reads my decisions from
  a root-owned file), the tool-less advisory, the analysis of a held file. They are no precedent for more.
- **Restrict, never loosen.** Toward Limbo, Heimdall only restricts a guest (`control.sock` has no loosening route); a human
  gives every verdict.
- **No third-party accounts.** A feature must not need users to sign up with an outside service (the URLhaus ClamAV feed
  went for that reason, 2026-11-18).
- **Light.** It runs on any system down to a Raspberry Pi: no polling where inotify or the kernel can tell; the long audits
  wait while a game runs (`yggdrasil-gametime`).
- **Code style.** Match the surrounding code; doc comments say why; table-driven tests; `gofmt -l .` prints nothing, `cargo
  fmt` clean. Think before coding, make the smallest change that solves the problem, touch only what the task needs, and
  decide first how you will verify it.

## 4. Contracts

All in [docs/CONTRACTS.md](docs/CONTRACTS.md), one section each. A change to one says `CONTRACT:` in the commit message and
updates that file in the same commit.

- Provided here: the API on 127.0.0.1:8930 and its callers; alerts (`/v1/alerts`, `/var/lib/heimdall/alerts.jsonl`, ATT&CK
  fields); `/v1/review`; the grant gate; the advisory and the held-file analysis Heimdall asks of Sarina; containment
  (`/etc/heimdall/contained`); trust, origin, maintenance, scan-files; held-file release and confirm; the device list;
  wifi-health; Wi-Fi trust (`heimdall-wifi-guard`, `wifi-trusted.json`, `state.json`); heimdall-multilink; heimdall-fileguard
  and heimdall-strip; the private microphone and heimdall-scrub; `defaults-off` and `security-tools`; the macvendor crate;
  the mesh; ports 8930 and 8931.
- Used from others: Sarina's session files and service API (Sarina `docs/ECOSYSTEM.md` §4); Limbo's `events.jsonl` and
  `control.sock` (Limbo docs/CONTRACTS.md, docs/EVENTS.md, docs/QUARANTINE.md); Yggdrasil's `yggdrasil-gametime status`.

## 5. Open work

docs/plans/BACKLOG.md and docs/plans/LOG.md (private; ask the owner).

## 6. Know-how

```
rust/heimdall/            the daemon and every command (heimdalld; the Wi-Fi helpers and former shell programs are links to it)
  src/sources/            agent sessions, vault, Limbo log, FIM, telemetry, /proc/net, journal, rogue router
  src/detect/             every detector; src/engine.rs, alert.rs, explain.rs, verify.rs, attack.rs, correlate.rs
  src/api.rs              the loopback API; src/response.rs, advisor.rs: the Limbo responder and Sarina's advisory
  src/cli/                one module per command (immunity, lan, wifitools, wifihealth, contain, grant, mesh, trust, ...)
  src/audit/              package, kernel and hardening audits (game time in gametime.rs)
rust/privacy/             heimdall-fileguard (downloads guard, safe file intake), heimdall-strip, lookalike.rs: docs/PRIVACY_PACK.md
rust/scrub/, scrub-ladspa/  location sounds and the voice disguise (the private microphone): docs/LOCATION_SOUNDS.md, VOICE_DISGUISE.md
rust/flyover-attack/      the flyover scorer; its tests prove the scrub defeats it
rust/multilink/           several internet connections at once: docs/MULTILINK.md
rust/macvendor/           the maker lookup crate (no dependencies; used by Yggdrasil Settings): docs/DEVICES.md
rust/yara-check/          YARA-X's compile check of rule drafts (its own workspace and package): docs/IMMUNITY.md
rust/tools/attack-table/  writes internal/attack/enterprise.tsv from one pinned MITRE release (by hand): docs/ATTACK.md
rust/parity/              differential harnesses (engine, state handover, shadow compare)
cmd/heimdalld/, internal/ the Go reference; internal/parity writes testdata/parity (the fixtures both languages run)
packaging/install.sh      the one file list; packaging/arch (heimdall-git), arch-private-mic, arch-multilink, arch-yara-check
packaging/net/, privacy/  NetworkManager dispatcher scripts, units, PipeWire/WirePlumber files; packaging/tests: Python tests
```

- Adding a detector: a Rust detector in `rust/heimdall/src/detect/` and its Go twin in `internal/detect/` (registered in
  `cmd/heimdalld/main.go`'s `newDetectors`), a table-driven test, the fixtures rewritten. A new source produces events and
  changes no existing detector. Every alert gets fixed `explain` text per detector and severity (`explain.rs`).
- `internal/attack/tags.tsv` maps detectors to ATT&CK techniques; the reasons and the gap list live in docs/ATTACK.md.
- `/usr/lib/heimdall/heimdalld-go` (the Go rollback of stage 1) is installed until the package stops building Go; the Rust
  binary hands an unknown command to it only while it exists.
- Tests never touch this computer's real network, Wi-Fi or audio: fake roots, `unshare -rn` namespaces, synthetic audio.
- The Wi-Fi helpers' Python programs (`packaging/net/`) are the reference `tests/cli_wifitools.rs` runs the ports against;
  the old shell programs are the reference of `tests/cli_shtools.rs`.
- Tooling trap: shell heredocs and scripted edits turn `\n` and `\u...` into real characters; use the editor for source
  with escapes, and never leave a raw invisible character in source (write it as an escape).
- Versions: `VERSION` is Heimdall's own (1.0.0 since 2026-11-11); the package is `heimdall-git` `VERSION-<build>`
  (Labyrinth_OS docs/VERSIONING.md).
