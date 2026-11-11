# Heimdall

The security agent of the **Artifex Ecosystem**. It runs on Labyrinth OS and on LykanOS (formerly Chymaera OS). It
watches [Sarina](https://github.com/Artifex-Technologies/Sarina), the local AI agent, from outside Sarina's process. It also watches
the computer itself: its connections, Wi-Fi, packages and kernels, settings, and the files that arrive. When something is wrong
it raises an alert a person (or another tool) can act on. When an AI agent is compromised it can stop it.

Every check runs on this computer. Heimdall itself never connects off the machine. A separate updater downloads the public
lists it checks against (threat lists, the security trackers, IP databases), and nothing about this computer is ever sent.

See Sarina's [`docs/ECOSYSTEM.md`](https://github.com/Artifex-Technologies/Sarina/blob/main/docs/ECOSYSTEM.md) for how the
repositories fit together, and [`CLAUDE.md`](CLAUDE.md) for Heimdall's coordination board.

## Why a separate process, and why Go

A monitor that shares a runtime, a dependency tree or a crash with the thing it watches is a weaker monitor. Heimdall is its own
binary, run as its own unprivileged `heimdall` user. It sees Sarina only through what Sarina writes to disk and what Sarina asks it
over its loopback API. It shares no memory with Sarina and imports none of Sarina's code.

Go, for the same reason [CrowdSec](https://github.com/crowdsecurity/crowdsec) and [Tailscale](https://github.com/tailscale/tailscale)
use it: one static binary, low CPU and memory for something that runs all the time. **The binary has no third-party
dependencies** (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)). **Arch Linux only**: both distributions are built on Arch.

## Why Rust: measured

The daemon, every command and the Python Wi-Fi helpers are ported to Rust ([`rust/`](rust/README.md)), one binary that takes
over at the switch ([`docs/RUST_SWITCH.md`](docs/RUST_SWITCH.md)). Measured on my desktop, old against new on the same input
(2026-11-11; a minus is a gain):

| Program | Was | Measured | Details |
| --- | --- | --- | --- |
| the daemon (`heimdalld run`) | Go | idle CPU 0.115 → 0.060 % of a core (−48 %), memory 39.8 → 13.6 MB (−66 %), context switches 21.9 → 0.4 a second, the engine 44 % faster; **worse: peak since start 49.3 → 73.3 MB (+49 %)** | [the daemon](rust/README.md#the-daemon) |
| 17 one-shot commands | Go | most 1.8-2.3 ms → 0.6-1.0 ms (−57 to −70 %) and 15-17 MB → 3.4-6.2 MB peak; `scan` −10 %; **worse: `intel-check tracker` +28 %, `kernel-check` peak +14 %** | [the commands](rust/README.md#the-one-shot-commands) |
| the Wi-Fi helpers (check, guard, notify) | Python | 23-49 ms → 0.6-3.3 ms (−89 to −97 %, 23-45 ms sooner each run), 14-23 MB → 4-5 MB | [the helpers](rust/README.md#the-wi-fi-helpers) |

Every case gave the same output in both. What the port found and fixed on the way (an injection phrase hidden by a look-alike
letter, a device name that crashed `lan scan`, a private key briefly readable by other accounts, and more) is listed with
each.

## What it does

### The AI agent's behaviour

| Detector | Catches |
| --- | --- |
| `injection-phrase` | Text that reads as an instruction override ("ignore all previous instructions", "you are now...") |
| `credential-shape` | Private keys, cloud and API tokens, password-looking assignments |
| `invisible-unicode` | Zero-width, bidi-override and tag characters that hide instructions from a human reader |
| `permission-escalation` | A session reporting permission denials (critical from 3) |
| `session-burst` | An abnormally high rate of new sessions (leaky bucket, CrowdSec-style) |

**Governance.** `POST /v1/review` runs the same injection, credential and invisible-Unicode checks on text Sarina is about to
store, and answers allow or deny. Sarina asks when `HEIMDALL_REVIEW_URL` is set. It fails open when Heimdall is not there; an
actual deny is respected. Every review is logged as an alert.

### Trust: the AI's behaviour files, signed by the owner ([docs/TRUST.md](docs/TRUST.md))

Sarina's rules, tool connections, skills and agent profiles are plain files. Most are writable by the user's account, so any
program running as the user could change how Sarina behaves. The owner keeps a list of the approved content, signed with a key only
root can read. Heimdall then raises a critical alert for any change, planted file or deletion that does not match (an approved
change is info). In enforce mode Sarina also refuses unapproved files. Every signed version is kept as a known-good copy, which
`heimdalld trust restore` puts back.

**Off by default** (`heimdalld trust mode off`), while Sarina and Heimdall are still being trained.

### Containment: stopping a compromised AI agent ([docs/CONTAIN.md](docs/CONTAIN.md))

Each step goes further only when the step before did not hold:

0. **Evidence first.** Before anything is stopped, Heimdall saves what it needs to learn what happened, in a root-only folder:
   - every process (Sarina's with the hash of the program that is really running);
   - connections, the graphics card and the loaded models;
   - the last hour of logs and Sarina's newest sessions;
   - copies of the behaviour files that are not as approved.
1. **Contain.** A lock (`/etc/heimdall/contained`) keeps Sarina from starting, also after a restart. Then Sarina's service and processes
   are stopped and the models are unloaded from the graphics card.
2. **Check.** A minute later: is anything back?
3. **Emergency, the last resort.** The approved files are restored. The login screen, the model server and everything on the
   graphics card are stopped. The card is reset and the computer restarts. The lock stays.

The owner releases Sarina in Settings > Security ("Restore and release", password asked) or with `sudo heimdalld contain release`.
The daemon only writes a request; a root unit (`heimdall-contain.path`) acts on it. **Automatic containment and the automatic
emergency are both off** until `/etc/heimdall/contain.json` switches them on.

### Quarantine and immunity ([docs/IMMUNITY.md](docs/IMMUNITY.md))

ClamAV is the reference: the signatures the world shares. Immunity is what Heimdall learns on top of it.

- **Held.** A suspicious file is moved into a root-only quarantine and ClamAV is asked at once. If ClamAV knows it, it is
  malware and stays held. If not, it is held and the owner is told. Heimdall also writes a report by reading the file, never
  running it: its kind, entropy, its ELF header for a program, the strings that stand out, and the first lines of a text file.
  Sarina reads the report and gives the owner an analysis.
- **Judged.** The owner can **Release** it (put back exactly as it was) or mark **It's malware**. Heimdall releases a file by
  itself only on proof that it was there before: the owner's signature, or its root-only daily **inventory** of the programs
  outside the packages, which must have seen exactly this file a day or more earlier. A request to release (from Sarina when a
  program that was there before breaks, or from anyone) only names the file; root checks the proof.
- **Learned.** Malware ClamAV does not know gets a fingerprint in `/var/lib/clamav/heimdall-immunity.hsb`, which ClamAV loads
  with its own database. Every scan from then on catches any copy of it.

Never moved: anything under `/usr`, `/boot`, `/proc`, `/sys`, `/dev` or `/run`, and any file an installed package owns.
`heimdalld scan-files` scans folders with ClamAV for the desktop (the downloads watch, Settings' scan).

### Known holes and safer settings ([docs/AUDITS.md](docs/AUDITS.md))

| Detector | Catches |
| --- | --- |
| `package-vulnerability` | An installed package version with a known vulnerability (Arch's security tracker, daily), with the fixed version and the update command |
| `kernel-vulnerability` | An installed kernel with known holes that a newer kernel fixes (the kernel CVE team's records from osv.dev, and CISA's list of vulnerabilities exploited in the wild, weekly). Critical only for an exploited hole in the running kernel |
| `hardening` | A setting that leaves a known kind of hole open where closing it costs nothing noticeable (a world-writable `/dev/kvm`, nested KVM, a few kernel settings), with the exact fix. Nothing is changed by itself |

`GET /v1/audit` answers what is open right now. Sarina's security advisor reads it and proposes the fixes to the owner in
order. `sudo heimdalld kernel-check` lists the holes per kernel.

### The computer and its network

| Detector | Catches |
| --- | --- |
| `file-integrity` | A watched file (`fim_paths`, and the agents' files when trust is on) changed, created or deleted |
| `resource-pressure` | Memory or load crossed a threshold |
| `baseline-drift` | A telemetry value that is an outlier against this computer's own learned normal range (streaming statistics, not a model) |
| `network-exposure` | An ecosystem port (8765, 8899, 44700, 8930) bound or reached from somewhere other than loopback |
| `connection-watch` | Each program's first connection to a new destination, and any connection to an address on a threat list (Spamhaus DROP, FireHOL Level 1, Emerging Threats): critical, with the `ufw` command to cut it off |
| `inbound` | Failed SSH logins from one address, port scans, an address the firewall keeps blocking |
| `wifi-safety` | The verdict on each Wi-Fi network joined: encryption, evil twins, sign-in pages, ARP and DNS spoofing, untrusted certificates, injected pages |

- **Where an address belongs.** Every remote address is named with its country and network from an offline IP database
  (IPinfo Lite or DB-IP Lite). Nothing is looked up online.
- **Wi-Fi guard.** `heimdall-wifi-guard` sets up trusted networks (remembered with their router's hardware address) and a VPN
  with a kill switch on every other network. It keeps the computer quiet on untrusted networks.
- **DNS block list.** NetworkManager's local DNS cache refuses malware, phishing and scam domains, updated daily.
- **Limbo.** Heimdall reads Limbo's audit log. With `limbo_auto_quarantine`, it restricts a guest that misbehaves and attaches
  Sarina's advisory. It can tighten a guest but never loosen one. Detectors: `limbo-guest` (a guest started without its
  firewall, or the firewall removed under it), `limbo-network` (a guest reaching for this computer or the home network:
  critical; a scan or IPv6: warning; reaching for this computer, the home network, or scanning also restricts it) and
  `limbo-exchange` (a guest tried to hand out a file ClamAV knows: warning; the guest is restricted and root keeps a copy by
  itself, or by hand with `sudo heimdalld immunity take-limbo SHA256`). Normal guest traffic (`net.flow`) is never an alert.
- **Device list ([docs/DEVICES.md](docs/DEVICES.md)).** On a network you trust, `heimdalld lan scan` (every 5 minutes, its own
  sandboxed unit) lists the devices on it: what each one is, who made it, its name, first and last seen. A device new to the
  network is a `lan-watch` warning. Settings shows the list under Wi-Fi & Network > Devices.
- **Wi-Fi checks ([docs/WIFI_HEALTH.md](docs/WIFI_HEALTH.md)).** `heimdalld wifi-health` measures the connection for about ten
  seconds and names the likely cause of slow Wi-Fi: weak signal, crowded channel, other devices, the router, or the internet
  provider. `--speed` adds a download test. It changes nothing, and any user may run it.
- **Verdicts.** Before a finding becomes an alert, `internal/verify` tries to disprove it separately from the detector:
  `confirmed`, `needs_validation` or `rejected` (a documentation example key drops to info). A verdict never raises a severity.
- **Maintenance windows.** `heimdalld maintenance on --for 2h --reason ...` (root, at most 4 h) turns routine alerts into info
  while the owner works on the system.

## Commands

| Command | What it does |
| --- | --- |
| `heimdalld run --config PATH` | The daemon (what `heimdall.service` starts) |
| `heimdalld scan --config PATH` | Scan once, print findings, exit 1 on any |
| `heimdalld scan-files [--state F] PATH...` | ClamAV scan of files or folders, as the calling user |
| `heimdalld trust init\|status\|mode\|sign\|forget\|restore\|verify\|watch` | The signed list of the agents' behaviour files |
| `heimdalld contain status\|now\|emergency\|evidence\|release` | Containment |
| `heimdalld immunity hold\|release\|release-if-proven\|add\|confirm\|list\|forget\|check\|inventory\|take-limbo` | Quarantine and immunity |
| `heimdalld immunity rule list\|show\|draft\|test\|approve\|reject` | YARA rules for held samples, owner-approved (docs/IMMUNITY.md) |
| `heimdalld grant status\|approve\|deny\|tier\|revoke\|off` | The one gate for an AI agent asking for more (docs/GRANTS.md) |
| `heimdalld mesh id\|init\|list\|enroll\|forget` | Alerts shared with your other computers, off by default (docs/MESH.md) |
| `heimdalld kernel-check [--all]` | Known holes per installed kernel |
| `heimdalld maintenance on\|off\|status` | Maintenance windows |
| `heimdalld origin IP...` | Where addresses belong (offline) |
| `heimdalld intel-check`, `heimdalld ipdb-check` | Validate downloaded lists before they are used |

Most changes need root (sudo): the keys, the samples and the locks are root's.

## The local API

Loopback only (`api_addr`, default `127.0.0.1:8930`); it refuses to bind anything else. Every endpoint but `/healthz`
answers only root, Heimdall's account, the accounts in `api_users` (default `sarina`) and the members of `api_groups`
(default `wheel`); the caller's account is read from the kernel, so clients send no token.

| Endpoint | Description |
| --- | --- |
| `GET /healthz` | liveness |
| `GET /v1/alerts?n=50` | the most recent alerts, newest first (max 500) |
| `GET /v1/audit` | what is open now: package and kernel holes, hardening gaps |
| `GET /v1/quarantine` | what Heimdall holds, with each file's report |
| `POST /v1/review` | governance: `{"kind","session_id","text"}` → `{"decision":"allow"\|"deny","reasons":[...]}` |
| `GET /v1/incidents` | related alerts grouped into incidents, newest first |
| `POST /v1/requests`, `GET /v1/requests` | an AI agent asks for a hand-off or a higher access tier; only the owner decides (`heimdalld grant`) |
| `POST /v1/rules/drafts`, `GET /v1/rules/drafts` | YARA rule drafts for held samples; tested and approved by root |

## Building and packaging

```bash
go build -o heimdalld ./cmd/heimdalld
go test ./... && go vet ./...
```

The tests are offline and use only the standard library: no Sarina, no model, no network.

`packaging/install.sh DESTDIR` installs everything (the daemon, the updaters, the Wi-Fi check and guard, the DNS block list, the
containment, request and inventory units, and the docs). Every package recipe calls it (`packaging/arch/PKGBUILD`, Labyrinth's
and LykanOS's `heimdall-git`), so the file list lives in one place. On a fresh install a pacman hook switches on the service,
its timers and the path units, never again on upgrades.

The service is sandboxed (`ProtectSystem=strict`, `ProtectHome=read-only`). The optional connection-watch drop-in
(`heimdall-connwatch.conf.example`) gives it read-only `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, to see which program owns a
connection and to read other users' files. Read access to Sarina's session folder (`/var/lib/sarina/sessions`) comes
from an ACL the package sets (`heimdall-sarina-read.conf` in tmpfiles.d: read and enter, never write), applied at boot and by
`heimdall-sarina-access.path` the moment Sarina's service makes the folder. Session files written before Heimdall was
installed stay unreadable (each is reported once); `sudo setfacl -R -m u:heimdall:rX /var/lib/sarina/sessions` opens them. See [`internal/config/config.go`](internal/config/config.go) for every setting and its
default.

## Design and references

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) covers the design phase by phase.
[`docs/REFERENCES.md`](docs/REFERENCES.md) is the ledger of every external project cited and what was taken from it.
[`docs/INTEGRATION-FAILURES.md`](docs/INTEGRATION-FAILURES.md) is the runbook for when Heimdall and Sarina do not reach each other.

## License

MPL 2.0. See [`LICENSE`](LICENSE).
