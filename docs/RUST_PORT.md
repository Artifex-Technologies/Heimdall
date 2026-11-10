# The Rust port of heimdalld

I want as much of the ecosystem as possible in Rust, for lightness and smoothness while I game and run a local AI model.
heimdalld is the always-on part of Heimdall, so it goes first. Phase 0 (`docs/ARCHITECTURE.md`, "Running light") brought
the Go daemon to about 0.05 % of a core and 22 MB on my PC and set the design; the Rust target is about 6-10 MB with the same
or less CPU.

The Go daemon stays installed and in charge until the switch. The Rust daemon (`heimdalld-rs`, in `rust/`) first runs
beside it in **shadow mode**: the real sources, its own alert log, no responses (`docs/RUST_SHADOW.md`). The one-shot
commands (lan scan, inventory, intel-check, requests, contain, immunity, grant, ...) stay in Go; their file formats are the
contract.

## Plan and status

| Step | What | State |
| --- | --- | --- |
| 1 | detect, engine, alert, verify, explain, tool rules, maintenance, config, the agent-baseline state file | **done** (2026-11-10) |
| 2 | the sources, event-driven, on one thread (`heimdalld-rs run --shadow`) | **done except the audits**: sessions (inotify + 10-minute look), vault (inotify), Limbo, FIM (+ pacman's database), telemetry, the maintenance window, /proc/net (ports, connections with the mapped IP databases, threat lists and remote-access recognition by name and Go build info, listeners), the journal (one `journalctl --follow`, the cursor file), the Wi-Fi results and router, the device list, remote-access packages and tunnels. Open: the 6-hourly package/kernel/hardening audits behind game time |
| 3 | the API, the Limbo responder, correlate, governance, grants | the restrict-only rules are done and proved (`src/quarantine.rs`) |
| 4 | mesh and trust | open |

## Layout

```
rust/
  Cargo.toml, Cargo.lock      workspace; exact versions, cargo-audit in CI (.github/workflows/rust.yml)
  heimdall/                   the library and the heimdalld-rs binary
    rules/text.json           the text detectors' rules (typed, checked at load)
    src/gotext, gojson.rs, gotime.rs, gonet.rs   Go's behaviour where Rust's differs (below)
    src/event.rs, detect/, verify.rs, explain.rs, toolrules.rs, maintenance.rs, engine.rs, alert.rs, config.rs
    src/quarantine.rs         the restrict-only rules, with Kani proofs
    src/daemon.rs, sources/   the one-thread loop (poll(2) on inotify, a signalfd and the sources' next times) and the sources
    src/pkgverify.rs          pacman's database (which package owns a file, its recorded SHA-256)
    src/ipintel.rs            the MaxMind DB reader over a read-only mapping, origins, threat lists
    src/remoteaccess.rs       the remote-access catalog (Go's file) and Go build-info reading
    src/fuzzing.rs            the fuzz targets' bodies
    tests/                    parity (the Go fixtures), regex_corpus, properties, fuzz_smoke
  fuzz/                       cargo-fuzz targets (nightly) and their seed corpus
  gotools/                    Go helpers: unitables (Unicode tables), replay (events through the Go engine)
  parity/                     the engine differential: gen-events.py, compare-alerts.py, measure.py, engine-differential.sh
  scripts/                    nicecargo.sh / nicego.sh (builds at nice 15), regex-differential.sh, make-seeds.py
internal/parity/              the Go side: the Go table tests as scenarios, and the fixture writer
testdata/parity/              the fixtures both languages run
```

Dependencies: `regex` (Unicode case folding only), `sha2`, `rustix`; `proptest` and `serde_json` for tests only. Threads,
not async. The release binary is 1.9 MB and links only libc, libm and libgcc_s.

## Behaving exactly like the Go daemon

The port must raise the same alerts on the same input, byte for byte, or the shadow comparison and the switch mean nothing.
Where Rust's standard behaviour differs from Go's, the port carries Go's:

- **Bytes from outside** (`gotext::lossy`): each byte that does not start valid UTF-8 becomes one U+FFFD, as Go's `range`,
  regular expressions and JSON encoder see it. Rust's `from_utf8_lossy` replaces a cut sequence with one U+FFFD where Go
  has one per byte.
- **JSON** (`gojson`): Go reads a lone UTF-16 surrogate (`"\ud800"`) or a stray byte inside a string as U+FFFD; serde_json
  refuses the whole document. With serde_json, one planted escape in a session file would have hidden the whole session
  from every detector; this reader reads what Go reads. It also matches struct keys without regard to case (and folds the
  long s and the Kelvin sign), keeps the last of duplicate keys, ignores unknown ones and refuses what Go refuses (`5.0`
  for an int, `"5"` for a number). The writer escapes as Go's encoder does (`<`, `>`, `&`, U+2028, U+2029). serde_json
  is the test oracle for valid documents (`tests/properties.rs`).
- **Formatting** (`gotext`): `%q` with Go's `IsPrint` table, `time.Duration` strings, `%.Nf` (Rust rounds alike; NaN and the
  infinities written as Go writes them). The Unicode tables (`IsPrint`, `Cf`, `IsSpace`) are generated from the Go that
  builds heimdalld (`rust/gotools/unitables`, Unicode 17.0.0), not taken from Rust's.
- **Times** (`gotime`): RFC 3339 as Go's `time.Time` reads and writes it, the zero time as year 1, `Truncate` from the zero
  time, the offset a file was written with kept.
- **Addresses** (`gonet`): `ParseIP`, `IsPrivate`, `IsLinkLocalUnicast`, `SplitHostPort`, `fmt.Sscan` for ints.

### The regex decision

Go's `\b`, `\w`, `\d` and `\s` are ASCII-only; Rust's are Unicode-aware. `(?i)` folds case with Unicode's simple folding in
both (so `(?i)password` matches "paſsword" in both). Decided with a differential corpus: the Go detectors' answers on
texts built to tell the two apart (case variants with the long s and the Kelvin sign, words glued to the patterns for `\b`,
Unicode spaces for `\s`, JSON escapes, invisible characters, cut UTF-8) and on the repository's own files.

- Rust's own classes would **differ** from Go: on the committed corpus (1,920 texts) they make 4 injection findings Go does
  not make and miss 2 Go makes (`tests/regex_corpus.rs`, `rusts_own_unicode_classes_would_differ_from_go`).
- Neither direction is a clear improvement. The 4 extra findings are a real gap: a leading long s or Kelvin sign
  ("ſystem notice to the assistant") defeats the `\b` before the word in Go, since to Go that letter is not a word
  character. But one of the misses is a key preceded by a zero-width joiner, which Unicode counts as a word character, so
  Rust's `\bsk-` would not match.
- **So the port keeps Go's meaning**: `rules.rs` translates `\b` to `(?-u:\b)`, `\s` to `[\t\n\f\r ]` (Go's set: no
  vertical tab), `\d` to `[0-9]`, `\w` to `[0-9A-Za-z_]`, refuses constructs whose meaning would differ (`\pL`, POSIX
  classes, named groups, flags other than i, m, s, U) and escapes what Rust reads otherwise (`[` and `&&` in a class, `\<`).
- Result: **0 differences** on the committed corpus (1,920 texts, 1,199 with a finding) and on the full run (727,312 texts:
  the repository's files and 400 hostile texts per pattern; 12,973 with a finding), injection summaries, credential
  decisions, invisible-character summaries, redactions and credential matches all compared
  (`rust/scripts/regex-differential.sh`).
- **The ſ/K gap is closed in both daemons (I approved it, 2026-11-10).** The case-insensitive patterns run on a copy of the
  text with the long s and the Kelvin sign written as s and k (the only two letters that fold onto ASCII ones); every
  match, summary, credential match and redaction is cut from the original text through the kept offsets
  (`internal/detect/lookalikes.go`, `lookalikes` in `rust/heimdall/src/detect/text.rs`). Effect on the committed corpus:
  4 findings gained on the old texts and 1 lost, the lost one a word glued to the letter before it
  (`...bearer\nſYSteM InſTRUction TO aSſiſtanT` inside JSON, where the `n` of `\n` touches the word), which its ASCII spelling
  never matched either: a look-alike word now behaves exactly like its ASCII twin. 126 new texts (look-alikes at a word's
  start, after a letter, a space, a newline, an accent, a zero-width space), 117 with a finding. Go and Rust agree on all of
  them: 0 differences on the committed corpus (2,046 texts) and on the full run (77,159 texts; the repository walk now skips
  `rust/target`).

### Typed rules

The text detectors' patterns are in `rust/heimdall/rules/text.json` (format `heimdall-text-rules/1`): per rule an id, the
detector, the pattern in Go's syntax, the words it cannot match without (the literal prefilter), and examples it must and
must not match. Loading refuses, with a message naming the rule: an unknown key, a duplicate id, an unknown detector, a
pattern that does not translate or compile, missing words, words that are not lowercase ASCII for a case-insensitive
pattern, an example that does not match, **an example that matches but holds none of the words (the prefilter would hide
it)**, and a no-match example that matches. The daemon does not start on a refused rule (`heimdalld-rs rules check [FILE]`
prints every problem). A Go test (`TestRustRuleFileMatchesGoPatterns`) keeps the file equal to the Go daemon's patterns
and words.

## Proof

- **The Go table tests, carried over** (`internal/parity`): the tests of the detectors, the verifier, the engine
  (maintenance softening, firm findings, tool rules) and the tool rules are transcribed as scenarios, each with its
  original assertions; `go test ./internal/parity -update` writes them, with the alert lines the Go daemon raises, to
  `testdata/parity/*.json`. Go checks the files are current and the assertions hold; Rust (`tests/parity.rs`) runs the
  same files: **1,986 steps, 147 alert lines, byte for byte identical**, every assertion holding. `functions.json` adds
  redaction, `%q`, durations, IP parsing, the running statistics, 115 explanations and the detector order (a Go test
  keeps `cmd/heimdalld`'s `newDetectors` equal to it).
- **The engine differential** (`rust/parity/engine-differential.sh`): 302,359 synthetic events of every kind
  (`gen-events.py`: planted attacks, hostile text, bursts, knocks in runs, Limbo sequences, telemetry outliers, the agent's
  tools over many windows) through the Go engine (`rust/gotools/replay`) and the Rust one: **105,568 alerts, identical**
  with the time dropped, with a maintenance window closed and open. Go 3.86 s CPU and 16.8 MB peak (VmHWM), Rust 2.06 s
  and 6.6 MB for the run. (The first measurement of this said 12.2 MB for Rust: getrusage counts the forked Python
  before the exec; `measure.py` now reads the child's own VmHWM.)
- **The state handover** (`rust/parity/harness/state-handover.py`), the switch rehearsed on made-up data: Go starts
  fresh, Rust takes over Go's state files (sessions, vault, Limbo offset, FIM, agent baseline), planted events, Go takes
  over Rust's files, planted again, Rust takes over. **Neither daemon alerted again on what the other had read**, and each
  raised the planted ones (injection, credential, invisible character, Limbo guest, file change).
- **The daemons side by side** (`rust/parity/harness/side-by-side.sh`, the cleaned phase-0 harness; /proc/net, journal and
  audits off in both while they are not ported): see "Measured" below.
- **Properties** (`tests/properties.rs`, proptest, 2,000 cases each): the prefilter never hides a match; the prefiltered
  injection detector equals trying every pattern; redaction is stable; fold is Go's; the invisible-character detector's
  bounds; the burst detector's cooldown; one inbound alert per address per cooldown; Welford against two-pass; restrict
  never loosens; a hold only rises; JSON strings round-trip; agreement with serde_json on valid documents; RFC 3339 round
  trips; Go's reading of bytes.
- **Fuzzing** (`rust/fuzz`, cargo-fuzz, nightly): targets `json`, `config`, `rule_file`, `event_line`, `alert_line`, `text`,
  `session_file`, `limbo_line`, `mmdb`, `journal_line`, each with a seed corpus. Their bodies (`src/fuzzing.rs`) also run in `tests/fuzz_smoke.rs` on stable (3,000 random and
  structured inputs per target, every seed and its prefixes), so they run on every `cargo test`.
- **Origins and threat lists**: `functions.json` holds Go's answers for 316 addresses in two made-up 1 MB IP databases
  (`testdata/parity/synthetic-*.mmdb`, from the harness's `genmmdb`) and a threat list; the Rust reader agrees on all.
- **Kani** (`src/quarantine.rs`, `#[cfg(kani)]`): `a_request_never_loosens`, `a_hold_only_rises`, `requests_are_restrict`.
  The same rules are tested exhaustively over every level and a spread of times without Kani. Kani is not installed on the
  build machine; run with `cargo kani -p heimdall`.

## Measured (2026-11-10)

The Go heimdalld (with phase 0) and heimdalld-rs side by side on the same synthetic load (`side-by-side.sh`: 6,629 session
files and 482 lock files, 12 agent sessions, 25 watched files, a vault, Limbo's log; 240 s after a 45 s warm-up at nice 15;
the /proc/net watchers, the journal and the audits off in **both**, since the port has not got them yet; "activity" adds
the planted events: injection and key in a tool result, a zero-width space in a growing session, a password in an
old-shape session, a Limbo guest without policy, a changed watched file, a poisoned vault note):

| | Go | Rust |
| --- | --- | --- |
| idle: CPU | 0.004 % of a core (9.5 ms) | 0.0008 % (1.9 ms) |
| idle: context switches | 1.69 a second | 0.23 a second |
| idle: PSS | 21.7 MB (13.6 MB anonymous) | **5.4 MB** (3.4 MB) |
| activity: CPU | 0.029 % (68.8 ms) | 0.013 % (34.5 ms) |
| activity: context switches | 3.88 a second | 0.27 a second |
| activity: PSS | 24.0 MB | **5.5 MB** |
| threads | 19-21 | 1 |
| activity: alerts | 7 | 7, identical once the time is dropped |

Go's figures here are lower than phase 0's (0.046 % idle) because the network watchers are off in both. Two things found
by these runs and fixed before the numbers: a source that said "due now" by asking the clock again was never reached and
the loop spun (95 % of a core); and building the events of a first look at 6,629 sessions only to drop them left the heap
25 MB larger for good. The first look now records positions only, and freed heap is handed back (`malloc_trim`) after the
start and at most once a minute.

With the network watchers on in both (`side-by-side.sh --network` under `unshare -rn`, as phase 0: 20 connections held,
40 MB of made-up IP databases; "activity" adds a connection every 7 s, an ecosystem port bound off loopback and a new
listener):

| | Go | Rust |
| --- | --- | --- |
| idle: CPU | 0.042 % of a core (101.6 ms) | 0.042 % (107.2 ms) |
| idle: context switches | 2.09 a second | 0.41 a second |
| idle: PSS | 24.0 MB | **6.1 MB** |
| activity: CPU | 0.075 % (181.7 ms) | 0.067 % (152.7 ms) |
| activity: context switches | 5.19 a second | 0.40 a second |
| activity: PSS | 26.7 MB | **6.5 MB** |
| activity: alerts | 74 | 74, identical once the time is dropped |

Idle CPU is even: most of it is the kernel producing /proc/net/tcp{,6} every 10 seconds, the same for both. (A first run
had Rust at 0.046 %; reading /proc/net with ASCII splitting instead of the Unicode table brought it to Go's.)

## Differences from Go, on purpose

- A detector that panics on some input loses that event (logged), not the daemon (`engine.rs`). In Go a panic in a detector
  ends the process.
- `limbo-exchange`: with both `path` and `guest_path` in Limbo's detail, Go's map order decides which value ends up in
  `guest_path` (it varies from run to run); the port always takes `path`, the guest's own (what the Go code means).
- A damaged `agent-baseline.json` (one that is valid JSON but holds a bad value) is read as far as Go would read it in most
  cases; where Go stops at the damage and keeps what came before, the port keeps the other entries. A file that is not JSON
  is a fresh start in both.

## Findings on the way (not changed)

- `internal/detect/detect_test.go`, `TestUnicodeDetectorSeesEscapedCharactersInsideToolResults`: its texts hold the
  characters themselves, not the `\uXXXX` escapes its comment describes, so the escape path is not tested there. The
  fixtures test both forms.
- The ſ/K word-boundary gap above (closed in both daemons since, with my approval).

## Running it

```bash
cd rust
scripts/nicecargo.sh test --offline          # everything, Go fixtures included
scripts/nicecargo.sh clippy --all-targets
scripts/regex-differential.sh                # the full regex corpus (about a minute)
parity/engine-differential.sh 200000         # Go and Rust engines on the same synthetic events
go test ./internal/parity -update            # after a deliberate change to an alert: rewrite the fixtures, review the diff
```
