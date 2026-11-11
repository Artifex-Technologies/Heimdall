# heimdalld in Rust

The Rust port of Heimdall: the daemon (`heimdalld run`), every one-shot command, and the three Wi-Fi helpers that were Python
(`heimdall-wifi-check`, `heimdall-wifi-guard`, `heimdall-wifi-notify`, which become links to the same binary). One binary,
`heimdalld-rs` until the switch, then `heimdalld`. How it was made to behave exactly like the Go and Python programs:
[docs/RUST_PORT.md](../docs/RUST_PORT.md) (the daemon), [docs/RUST_CLI.md](../docs/RUST_CLI.md) (the commands and the
helpers); the switch: [docs/RUST_SWITCH.md](../docs/RUST_SWITCH.md), the shadow week: [docs/RUST_SHADOW.md](../docs/RUST_SHADOW.md).

```bash
cd rust
scripts/nicecargo.sh build --release --locked     # target/release/heimdalld-rs
scripts/nicecargo.sh test --offline               # everything, the Go fixtures and the side-by-side runs included
```

## Why Rust: measured

Measured on 2026-11-11 on my desktop (16 threads, 64 GB), Go 1.27.3, Rust 1.99.1, Python 3.14.9. Old: the Go heimdalld built
from the source of `9cfdeca` as the PKGBUILD builds it, and the Python helpers of `9cfdeca`. New: the Rust release build of
`9cfdeca`. Change is (old − new) / old, so a minus is a gain. Times are the median of 30 runs each, p10-p90 in brackets.
Method and script: [How these numbers were measured](#how-these-numbers-were-measured).

### The daemon

| Metric | Go | Rust | Change |
| --- | --- | --- | --- |
| CPU over the same idle minute | 69.0 ms (0.115 % of a core) | 35.8 ms (0.060 %) | −48 %, 33.2 ms less a minute |
| CPU since start (26 h each) | 107.4 s (0.111 % of a core) | 47.4 s (0.050 %) | −55 % |
| context switches a second | 21.9 | 0.40 | −98 % |
| memory now (RSS) | 39.8 MB | 13.6 MB | −66 %, 26.2 MB less |
| of it the program's own (anonymous) | 30.2 MB | 8.0 MB | −73 % |
| **peak since start (VmHWM)** | 49.3 MB | 73.3 MB | **+49 %, 24.0 MB more** |
| threads | 20 | 2 | |
| the engine: 100,000 synthetic events | 1.96 s (1.95-2.02), 51,000 a second | 1.09 s (1.09-1.11), 91,500 a second | −44 %, 0.87 s faster |
| the engine: CPU | 2.01 s | 1.09 s | −46 % |
| the engine: peak RSS | 18.1 MB | 7.7 MB | −57 % |
| binary on disk | 10.4 MB | 6.3 MB, with the commands and the Wi-Fi helpers | −39 %, 4.0 MB less |

- The first seven rows are the two daemons running on this computer, read from /proc over the same minute: the Go one in
  charge, the Rust one in its shadow week (the same sources and detectors, but it serves no API and takes no action, while
  the Go one also answers Settings, Sarina and the check-up). The running shadow binary is the build of 2026-11-10 morning.
  Go's memory moves with its garbage collector: 28.1 MB a few minutes before the window (Rust 13.4 MB).
- **Worse in Rust: the peak.** It does not stay (13.6 MB now), and I have not traced which step makes it. On made-up data
  the 6-hourly audit round peaked lower in Rust (35.8 MB against 56.1 MB, docs/RUST_PORT.md), but `kernel-check` below also
  peaks 14 % higher in Rust, so reading the real kernel CVE list is the first suspect. To look into before the switch.
- The engine rows: `rust/parity/gen-events.py`'s events through each engine (Go: `rust/gotools/replay`), 5 runs each:
  53,017 alerts from each, identical once the time is dropped.
- Earlier controlled runs side by side on the same made-up load (docs/RUST_PORT.md, "Measured"): idle PSS 21.7 MB → 5.4 MB,
  with the network watchers 24.0 → 6.1 MB, with the audits 26.6 → 6.5 MB; idle CPU even with the network watchers on (most
  of it is the kernel writing /proc/net).

More accurate:

- The same alerts as Go: 1,986 fixture steps and 147 alert lines byte for byte; 105,568 alerts identical on 302,359
  synthetic events; 0 differences on 727,312 texts through the patterns; side by side 7/7, 74/74 and 34/34 alerts identical.
- Found by the port, fixed in both: a long s or Kelvin sign at the start of a word ("ſystem notice to the assistant") hid
  an injection phrase from Go's ASCII `\b`.
- Found by the port's tests, fixed in both: a killed Sarina process its parent had not collected yet counted as running, so
  a held containment could look broken and, with the automatic emergency on, stop the desktop for nothing.
- Go: a detector that panics on hostile input ends the whole daemon. Rust loses that one event.
- Go: with both `path` and `guest_path` in a Limbo event, map order decided which one became `guest_path`, differently from
  run to run. Rust always takes the guest's own `path`.
- Go: a package or kernel folder whose name is not UTF-8 was reported again every 6 hours. Rust reports it once.
- Go: an empty state path wrote a stray `.tmp` file in its working folder. Rust writes nothing.
- Go sorts package findings and an incident's members unstably, so equal ones may change places. Rust sorts stably.

### The one-shot commands

| Command (made-up input) | Go | Rust | Change | Peak RSS, Go → Rust |
| --- | --- | --- | --- | --- |
| `version` | 1.89 ms (1.79-2.18) | 0.57 ms (0.53-0.63) | −70 %, 1.32 ms faster | 14.9 → 3.4 MB (−77 %) |
| `scan` (6,641 sessions, Limbo, a vault, 25 watched files) | 78.3 ms (77.3-79.7) | 70.3 ms (69.8-71.1) | −10 %, 8.0 ms faster | 43.2 → 37.2 MB (−14 %) |
| `origin` (40 addresses) | 2.34 ms (2.21-2.46) | 0.83 ms (0.79-0.91) | −64 %, 1.51 ms faster | 16.9 → 6.2 MB (−63 %) |
| `ipdb-check` (two 1 MB databases) | 1.83 ms (1.74-1.96) | 0.61 ms (0.57-0.65) | −67 %, 1.22 ms faster | 15.4 → 3.9 MB (−74 %) |
| `intel-check list` (5,000 networks) | 6.91 ms (6.82-7.04) | 2.88 ms (2.79-2.95) | −58 %, 4.04 ms faster | 19.6 → 4.9 MB (−75 %) |
| **`intel-check tracker`** (6,000 advisories) | 13.4 ms (13.3-13.7) | 17.1 ms (16.7-17.6) | **+28 %, 3.74 ms slower** | 22.7 → 20.8 MB (−9 %) |
| `kernel-check` (9,000 kernel CVEs) | 37.0 ms (36.2-37.5) | 35.0 ms (34.6-35.4) | −5 %, 2.0 ms faster | **27.0 → 30.9 MB (+14 %)** |
| `lan list` (60 devices) | 2.31 ms (2.17-2.38) | 1.00 ms (0.93-1.05) | −57 %, 1.31 ms faster | 17.2 → 5.1 MB (−71 %) |
| `lan scan` (no network: the 5-minute timer's quick answer) | 1.96 ms (1.86-2.13) | 0.66 ms (0.61-0.73) | −66 %, 1.29 ms faster | 15.1 → 4.6 MB (−69 %) |
| `maintenance status` | 2.00 ms (1.91-2.13) | 0.64 ms (0.60-0.70) | −68 %, 1.36 ms faster | 15.2 → 4.5 MB (−70 %) |
| `grant status` | 1.83 ms (1.72-1.99) | 0.58 ms (0.53-0.63) | −68 %, 1.25 ms faster | 14.9 → 3.7 MB (−75 %) |
| `contain status` | 1.82 ms (1.72-1.90) | 0.58 ms (0.54-0.62) | −68 %, 1.24 ms faster | 14.9 → 3.7 MB (−75 %) |
| `remote list` | 1.95 ms (1.83-2.06) | 0.66 ms (0.63-0.75) | −66 %, 1.29 ms faster | 15.3 → 4.1 MB (−73 %) |
| `trust status` | 1.83 ms (1.73-1.97) | 0.59 ms (0.55-0.64) | −68 %, 1.25 ms faster | 14.9 → 3.9 MB (−74 %) |
| `immunity list` | 1.82 ms (1.72-1.94) | 0.58 ms (0.54-0.63) | −68 %, 1.24 ms faster | 14.9 → 3.9 MB (−74 %) |
| `scan-files` (300 files, one ClamAV call) | 4.68 ms (4.48-4.91) | 2.81 ms (2.71-2.99) | −40 %, 1.87 ms faster | 20.0 → 4.6 MB (−77 %) |
| `scan-files --state` (300 files, unchanged) | 2.57 ms (2.49-2.84) | 1.15 ms (1.10-1.22) | −55 %, 1.42 ms faster | 17.3 → 4.8 MB (−72 %) |
| `wifi-health` (no Wi-Fi route: the quick answer) | 1.82 ms (1.76-1.95) | 0.62 ms (0.57-0.65) | −66 %, 1.20 ms faster | 14.9 → 4.3 MB (−71 %) |

- Every command printed the same output in both (times blanked).
- Most of a short Go command's time is starting the Go runtime: about 1.8 ms and 15 MB before any work, against about
  0.5 ms and 3.5 MB for Rust.
- **Worse in Rust:** `intel-check tracker` is 28 % slower (it reads Arch's tracker, a large JSON file; not profiled yet; it
  runs once a day), and `kernel-check` peaks 3.9 MB higher.
- `scan` gains least (−10 %): its time is reading 6,641 files.

More accurate:

- The same output, files and exit codes as Go: `lan` 4,091 fixture cases and a whole scan of a made-up network; `intel` 80
  runs; `immunity` 73 steps; `contain` and the admin commands 151 runs and 447 fixture cases; `wifi-health` 3,361 parser cases,
  160 whole reports and 19 runs; `trust`, `mesh`, `scan` 155 fixture cases and 132 steps (docs/RUST_CLI.md).
- Go: a device announcing a name whose lowercase is longer than the name (`Ⱥ`, bytes that are not UTF-8) made `lan scan`
  panic, every 5 minutes while that device answered. Rust leaves the name out.
- Go: a `/proc/net/route` line of 7 fields would make `lan scan` panic. Rust skips it.
- Go: holding a file whose name has a character above U+00FF kept an empty sample that could never be released. Rust keeps
  a good one.
- Go: a damaged signing key (its public half not from its seed) signed a list that never verifies. Rust refuses the key.

### The Wi-Fi helpers

| Helper and case | Python | Rust | Change | Peak RSS, Python → Rust |
| --- | --- | --- | --- | --- |
| check: a whole check (online tests held by the guard) | 48.6 ms (47.8-49.3) | 3.26 ms (2.93-3.42) | −93 %, 45.3 ms faster | 23.2 → 4.8 MB (−79 %) |
| guard pre-up: an untrusted network, the lockdown before any traffic | 26.2 ms (25.8-27.0) | 1.40 ms (1.25-1.56) | −95 %, 24.8 ms faster | 14.1 → 4.5 MB (−68 %) |
| guard up: a trusted network, its router checked | 27.0 ms (26.7-27.8) | 2.02 ms (1.84-2.24) | −93 %, 25.0 ms faster | 14.1 → 4.3 MB (−70 %) |
| guard up: an untrusted network, quiet, lockdown, VPN | 27.8 ms (27.6-28.1) | 3.18 ms (2.95-3.35) | −89 %, 24.6 ms faster | 14.1 → 4.3 MB (−69 %) |
| guard down | 26.4 ms (26.0-26.8) | 1.38 ms (1.27-1.54) | −95 %, 25.0 ms faster | 14.1 → 4.3 MB (−70 %) |
| guard status | 27.0 ms (26.3-55.9) | 2.00 ms (1.75-3.18) | −93 %, 25.0 ms faster | 14.1 → 4.3 MB (−69 %) |
| notify: an unsafe network, one notification | 23.4 ms (23.2-24.2) | 0.63 ms (0.56-0.68) | −97 %, 22.8 ms faster | 16.7 → 4.1 MB (−75 %) |
| notify: a network already shown, nothing to do | 23.6 ms (23.1-24.0) | 0.61 ms (0.58-0.69) | −97 %, 23.0 ms faster | 16.7 → 4.1 MB (−76 %) |
| on disk | 39.8 KB of scripts, plus Python | 0 bytes more: links to heimdalld | |

- Every case printed the same output in both.
- Python's own start (`python3 -c pass`) is 9.3 ms and 9.9 MB of it; the rest is importing the modules (`json`, `ssl`,
  `urllib`, `subprocess`) and the work. NetworkManager waits for `pre-up` before the link comes up, so that time was on every
  Wi-Fi connection.

More accurate:

- The same output, files and calls as the Python programs: 493 runs in fake roots (check 64, guard 375, notify 54) and
  36,988 parser cases against Python itself (about 296,000 more with other seeds).
- Found by the port, fixed in both: a network name ending in a backslash made the check say "not on Wi-Fi" and check nothing.
- Found by the port, fixed in both: the check called a network trusted without the router remembered with it, so a
  stranger's copy of a trusted network escaped the daemon's router watch.
- Found by the port, fixed in both: `vpn-import` wrote the WireGuard private key into a /run file other accounts could read,
  and made it private only afterwards.
- Found by the port, fixed in both: a file holding JSON that is not an object stopped each helper with a traceback (the
  guard in `pre-up`, before it could lock the network).
- Decided with the port, in both: a trusted network whose router did not answer is now treated as untrusted.

### How these numbers were measured

```bash
cd rust && scripts/nicecargo.sh build --release --locked && cd ..
python3 -I rust/parity/bench-port.py --json /tmp/bench.json      # about 4 minutes; --only daemon,engine,cli,wifi
```

- `rust/parity/bench-port.py` builds the old side from git (`git archive 9cfdeca`, then `go build -trimpath -ldflags "-s -w"`;
  the Python helpers by `git show 9cfdeca:...`), so it works after the Go and Python files are gone. `--go-commit` and
  `--py-commit` pick others.
- Old and new run one after the other, alternating which goes first, 30 times each after one unmeasured run of each (the
  engine 5 times), one process at a time, at nice 19.
- A small C launcher (built by the script with `cc`) starts each program and reports its wall time, user + system CPU and
  peak RSS from `wait4`. Started from Python directly, a program's peak would include Python's own 12 MB: Linux counts the
  memory a process had before `exec`. The floor, `/usr/bin/true`: 0.29 ms and 1.6 MB.
- The programs run in a user, mount and network namespace of the script's own: no network (only a loopback), a made-up
  `/etc/heimdall`, `/var/lib/heimdall`, `/run` and Wi-Fi interface, and a stand-in (a small C program answering from a file in
  about 0.3 ms) over every outside tool a program starts: nmcli, ip, ss, systemctl, nft, ping, notify-send, clamscan, iw.
  Nothing on this computer or its network is touched. CPU and peak RSS include the stand-ins a program starts (the same
  calls for both).
- Inputs: `rust/parity/harness/setup-env.py --audits` (6,629 session files and 12 agent sessions, a vault, Limbo's log, 25
  watched files, a tracker of 6,000 advisories, a kernel list of 9,000 CVEs), the made-up IP databases in `testdata/parity`, a
  made-up threat list and device list, 300 files to scan; for the helpers, made-up networks answered by the stand-ins.
- The daemon: `/proc` of `heimdall.service` and `heimdall-shadow.service` over the same 60 seconds, read-only (CPU from
  every thread's `schedstat`, context switches of every thread, `VmRSS`, `RssAnon`, `VmHWM`).
