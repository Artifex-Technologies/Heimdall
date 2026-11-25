# Contracts with other repositories

What other projects of the Artifex Ecosystem rely on from Heimdall, and what Heimdall relies on from them. One section per
contract: what it is, who uses it, where it lives in the code. Changing any of them is a contract change: the commit message
says `CONTRACT:`, this file changes in the same commit, and the other repository is told (its maintainers' handoff notes).
Adding an optional field or key is backwards compatible; renaming or removing one, or changing a shape, exit code or first
line, is not.

The daemon in charge is the Rust `heimdalld` (`rust/heimdall`, since 2026-11-19); the Go sources (`cmd/`, `internal/`)
remain the reference the parity fixtures are written from, and their package names appear below where a contract was first
written against them.

## Ports

`8930`: Heimdall's API, loopback only. `8931`: the mesh, off by default, on one non-loopback address I choose. Both are in
Sarina's `docs/ECOSYSTEM.md` port registry.

## The API and who may call it

- **What:** HTTP on `127.0.0.1:8930`. Every endpoint but `/healthz` answers only root, heimdalld's account, `api_users`
  (default `sarina`) and members of `api_groups` (default `wheel`), identified by the kernel from `/proc/net/tcp`; clients
  send nothing extra. A client running as another account needs adding to `api_users`.
- **Who:** Sarina (service and CLI), Yggdrasil's panel and Settings, Labyrinth OS's `labyrinth-sarina-checkup` and
  `labyrinth-selfcheck` (`/healthz`), LykanOS's `lykanos-security.conf` (`api`).
- **Where:** `rust/heimdall/src/api.rs`; Go `internal/api` (`access.go`, `status.go`'s `ListenAndServeLoopback`).

## Alerts: `GET /v1/alerts` and `/var/lib/heimdall/alerts.jsonl`

- **What:** one JSON object per alert, in the API and one per line in the file. Each carries `explain` (what happened, how
  serious, what Heimdall did, what to do; fixed text per detector and severity). Since 2026-11-18 an alert may carry
  `attack` (technique IDs such as `"T1557.002"`, in the map's order) and `explain.attack` (`[{"id", "name"}]`, the same IDs
  with MITRE's names, a sub-technique as "Parent: Sub"); both are left out when the detector has no tag. A tag says what the
  detector watches, never that a technique is covered. MITRE's page is
  `https://attack.mitre.org/techniques/<ID with "." as "/">/`, opened only on a click. Which detector gets which tag
  (`internal/attack/tags.tsv`) may change with a note; the reasons and the gap list are in [ATTACK.md](ATTACK.md).
- **Who:** Yggdrasil Settings > Security (the Explain button; the names from `explain.attack`), the panel's notifications
  ("What to do"), Sarina (both fields, from the API and the file).
  Field names in an alert's `fields` are stable (Sarina reads `verdict` and `verdict_reason` before advising); `hardening`
  alerts may carry `cve`, and `GET /v1/audit`'s `hardening` entries too (omitted when empty).
- **Where:** `rust/heimdall/src/alert.rs`, `explain.rs`, `attack.rs`, `verify.rs`.

## Sarina's session files (Heimdall reads)

- **What:** `/var/lib/sarina/sessions/*.json`, the shared folder the Sarina service writes (`agent_session_dir`;
  `session_id`, `messages` as objects with `role`/`content`/`tool_calls`). A workspace's `.port_sessions/agent/<id>.json`
  has the same shape; the older flat `messages: []string` shape under `.port_sessions/` is still accepted. Sarina writes
  each file atomically (temp file and rename) and keeps the shape stable (`sarina doctor`'s `session_contract` check).
  Heimdall never writes there and never imports Sarina's code. Access: an ACL for Heimdall's account (read and enter, never
  write), kept by `heimdall-sarina-access.path`.
- **Who:** provided by Sarina (`docs/ECOSYSTEM.md` §4a); read by Heimdall.
- **Where:** `rust/heimdall/src/sources/agent.rs`; Go `internal/sources/agentsource`.

## Review: `POST /v1/review` (Sarina asks, opt-in)

- **What:** Sarina's shared scan gate (memory writes) asks Heimdall to review text after its own checks pass, opt-in via
  `HEIMDALL_REVIEW_URL` on Sarina's side (the old `SENTRY_REVIEW_URL` is read when the new one is unset). A `"deny"` folds
  into Sarina's blocked result. Fails open when Heimdall is absent, fails closed on an actual verdict
  ([ARCHITECTURE.md](ARCHITECTURE.md), Phase 4). A breaking change to the request or response JSON changes Sarina's
  `heimdall.rs` in the same step.
- **Who:** Sarina (`heimdall.rs`, called from `guard.rs`; `docs/ECOSYSTEM.md` §4b).
- **Where:** `rust/heimdall/src/governance.rs`, `api.rs`; Go `internal/governance`, `internal/api/review.go`.

## The grant gate: `POST /v1/requests` and `/etc/heimdall/grants.json`

- **What:** Sarina files requests (`POST /v1/requests`: `kind` escalation|access_tier, `detail`, `session_id`, `reason`) and
  reads my answers from `/etc/heimdall/grants.json` (root's; `access_tier` cap and `escalations` with `tier`,
  `session_id`, `until`), never over HTTP. Off until I switch it on (`sudo heimdalld grant tier N`). Either JSON shape
  changing is a contract change in both repositories. [GRANTS.md](GRANTS.md).
- **Who:** Sarina (`heimdall.rs`: the access-tier reading and the tiers' router).
- **Where:** `rust/heimdall/src/grants.rs`, `cli/grant.rs`.

## Heimdall asks Sarina: the advisory on a new hold

- **What:** after a new Limbo quarantine, Heimdall asks the local Sarina service (`sarina_url`, loopback) for an opinion:
  a session with `tool_allowlist: []`, the alert framed as untrusted data, the reply attached to the quarantine as an
  advisory. Heimdall verifies the service reports 0 tools and sends nothing otherwise (an older service ignores the field).
  An advisory never changes a record's status. Uses Sarina's `POST /v1/sessions` and `/chat`.
- **Who:** Sarina's service (`docs/ECOSYSTEM.md` §4c).
- **Where:** `rust/heimdall/src/advisor.rs`.

## Heimdall asks Sarina: analysis of a held file

- **What:** root's `heimdalld immunity analyze --sarina SHA256` (and, with `sarina_analysis` = `"auto"`, a queued request
  after a new hold ClamAV does not know) lends an uncompressed read-only copy at
  `/var/lib/heimdall-sarina-share/<sha256>.sample` (root:sarina 0440), named in the request as Sarina's sandbox sees it,
  `/quarantine/<sha256>.sample`. The session: `tool_allowlist: ["reverse_engineer"]`, `max_turns` 12, `max_tool_calls` 10,
  `timeout_seconds` 300; nothing is sent unless the service reports `tools: 1` (`sarina_contract_tools_mismatch`). When
  `/var/lib/sarina/.local/share/labyrinth/rea-work/bsim/library.mv.db` is a plain file, the request also asks
  `reverse_engineer` command `similar`, and the kept analysis records `similar: true`. The answer is untrusted, kept as
  `sarina_analysis` on the held file's index entry (a YARA block in it is only a rule draft); never while Sarina is
  contained; one at a time. `sarina_analysis` in `/etc/heimdall/config.json` is the switch Settings shows.
  [IMMUNITY.md](IMMUNITY.md), "Sarina's analysis".
- **Who:** Sarina (`reverse.rs`; `docs/ECOSYSTEM.md` §4d), Yggdrasil Settings (the switch).
- **Where:** `rust/heimdall/src/cli/immunity/sarina.rs`, `immunity.rs`.

## Containment: `/etc/heimdall/contained` and `heimdalld contain`

- **What:** the lock `/etc/heimdall/contained` is written first when Sarina is contained; Sarina refuses to start while it
  exists and Limbo stops and refuses her agents' runs. `heimdalld contain status`, `sudo heimdalld contain release`
  (restore the approved files, then lift the lock; same exit codes and messages in Rust and Go). [CONTAIN.md](CONTAIN.md).
- **Who:** Sarina (checks the lock), Yggdrasil Settings > Security ("Restore and release"), LykanOS and Labyrinth's
  security integration files (`contained`, `release`).
- **Where:** `rust/heimdall/src/contain.rs`, `cli/contain.rs`.

## Trust, origin, maintenance (commands others run)

- **What:** `heimdalld trust status|sign|restore` and the files it keeps (Sarina's `trust` reads the same files);
  `heimdalld origin IP...` prints `IP  ORIGIN` lines; `heimdalld maintenance on|off|status`; `heimdalld scan-files` prints
  `INFECTED PATH: SIGNATURE` lines with exit codes 0 (clean), 1 (found), 2 (error).
- **Who:** Sarina (trust, origin), Labyrinth OS (`labyrinth-agent` uses maintenance; the downloads scan uses scan-files).
- **Where:** `rust/heimdall/src/cli/trust.rs`, `cli/maintenance.rs`, `cli/scan.rs`, `ipintel.rs`.

## Held files: `heimdalld immunity release|confirm`

- **What:** `heimdalld immunity release ID` and `heimdalld immunity confirm ID`, with their exit codes and messages.
- **Who:** Yggdrasil Settings and the security integration files (`held_release`, `held_confirm`).
- **Where:** `rust/heimdall/src/cli/immunity.rs`.

## Limbo's event log (Heimdall reads)

- **What:** Limbo's `events.jsonl` (spec: Limbo's `docs/EVENTS.md`: one JSON object per line with `time`, `kind`, `guest`
  and a flat string-valued `detail`). The live log `/var/lib/limbo/state/events.jsonl` is `root:limbo-heimdall` 0640;
  heimdalld gets that group from the drop-in `packaging/arch/limbo-integration.conf.example`. Detectors: `limbo-guest`
  (Limbo's safety ordering from outside: a guest started with no firewall policy first, a policy removed under a running
  guest; `image.rejected`, `gate.blocked`), `limbo-network` (`net.anomaly` by `reason`, `net.capped`; `sinkhole.dns` and `sinkhole.connect`: a sealed guest calling
  out, each target once a guest, at most 8, guest data quoted and cut; `sinkhole.stop` starts a guest afresh), `limbo-exchange`
  (`exchange.held`, `exchange.fail`; detail `path` becomes alert field `guest_path`). `net.flow`, `net.blocked` and
  `exchange.file` are deliberately not alerts. Limbo adding kinds or keys is compatible; renaming or removing them is a
  contract change on both sides. Heimdall treats a tap `vl-<guest>` on its bridge `lb-<guest>` as Limbo's own (Limbo pins
  the names in its `virt` names). `lan-watch` reads `sinkhole.start` (detail `addr`, `dns_port`, `tcp_port`,
  `udp_port`) and `sinkhole.stop` (`addr`): between them a listener on that gateway address and those ports (the DNS port
  over UDP and TCP) is Limbo's sinkhole responder, not a new listener (HEI-6); outside a run it is reported as any other.
  `limbo-guest` also reads `wine.start` from `limbo wine`'s own log (the person's `~/.local/state/limbo/events.jsonl`, same
  line format, guest `wine:<prefix>`; `limbo_event_log` names one log, so pointing it there is a choice of that log): the
  detail `sha256` (the program file's) is looked up in the immunity store's index (`immunity.json`); a `held`, `immune` or
  `reference` sample is critical, a `suspect` a warning, a `released` one or an unknown hash nothing (HEI-10). Such an
  alert starts no response: a Wine run is no guest `control.sock` can restrict. The other `wine.*` kinds are not alerts.
- **Who:** provided by Limbo; read by Heimdall.
- **Where:** `rust/heimdall/src/sources/limbo.rs`, `detect/stateful.rs`.

## Heimdall restricts a Limbo guest: `control.sock` (restrict-only)

- **What:** I decided (2026-10-04) that Heimdall may cut a guest's network and that a human must approve any verdict.
  Heimdall calls Limbo's `control.sock` (`POST /v1/quarantine`, `POST /v1/quarantine/{id}/advisory`, and the read-only
  `GET /v1/guests/{name}` to skip a torn-down guest). That socket has no route to release a guest, lift a hold, lower a
  level, tear a guest down or give a verdict, so a compromised Heimdall can only make a guest more restricted. Triggers:
  `limbo-guest` critical on `guest.start` / `policy.remove`; `limbo-network` warning or higher on `net.anomaly` with
  `reason` `host_probe`, `lan_probe` or `scan`; `limbo-exchange` warning or higher on `exchange.held`; always a
  re-validated guest name, always level `restrict`. Only in `heimdalld run`, never `scan`. A Limbo outage never costs
  Heimdall its own alerts. Spec: Limbo's `docs/QUARANTINE.md`. Held files Limbo kept are copied into Heimdall's store by
  root's `heimdall-requests.service` (`immunity take-limbo`), and the analysis asks `POST /v1/sample-runs` on Limbo's
  admin socket.
- **Who:** provided by Limbo; used by Heimdall.
- **Where:** `rust/heimdall/src/response.rs`, `quarantine.rs`, `cli/immunity.rs`.

## Game time (Heimdall asks Yggdrasil)

- **What:** before each package audit, kernel audit and hardening check, heimdalld runs `/usr/bin/yggdrasil-gametime
  status`: exit 0 means a game runs (the job waits, asks again every 5 minutes, and logs the reason from the first stdout
  line, `A game is running: REASON.`); exit 1 means none; a missing tool, any other exit or no answer within 10 s means run
  as before. The downloads guard's heavy half waits the same way (asked once a minute while something waits).
  `HEIMDALL_GAMETIME` names another tool (tests use it). Watching (alerts, detectors, the responder) never asks.
- **Who:** provided by Yggdrasil; used by heimdalld and heimdall-fileguard.
- **Where:** `rust/heimdall/src/audit/gametime.rs`, `daemon.rs`; `rust/privacy/src/gametime.rs`.

## The maker lookup crate (`rust/macvendor`)

- **What:** the crate `heimdall-macvendor`, used as a git dependency pinned to a commit (`rev`). Its public API (`global`,
  `lookup`, `lookup_str`, `Table::lookup_oui`, `Answer`, `Vendor`, `is_local`, `parse_mac`) changes only with a matching
  change where it is used. It stays free of dependencies, so it builds anywhere Settings does (a Raspberry Pi too).
- **Who:** Yggdrasil Settings (makers of Wi-Fi access points and their vendor extras), LykanOS's tools.
- **Where:** `rust/macvendor`. [DEVICES.md](DEVICES.md).

## The device list: `GET /v1/lan/devices`, `heimdalld lan`

- **What:** `GET /v1/lan/devices` returns `{networks: [{uuid, ssid, first_scan, last_scan, devices: [{mac, ip, name, names,
  vendor, model, kind, owner_kind, services, private_mac, first_seen, last_seen}]}], status, status_uuid, status_time}`.
  `kind` (the guess) is one of router, this, tv, speaker, printer, phone, computer, console, smart, private, other;
  `owner_kind` (omitted when unset) is what I said a device is: `pkexec /usr/bin/heimdalld lan kind MAC KIND|guess`.
  `status` can be `not_trusted`, `not_home`, `router_changed`, `offline`. "Scan now": `systemctl start --no-block
  heimdall-lan-scan.service` (polkit rule `50-heimdall-lan-scan.rules`: wheel, active local session).
- **A look at a network that is not home:** `heimdalld lan look [--wait SECONDS] [UUID]` (any account, no password; Rust
  only) listens for SECONDS (default 8, held to 1-60) on active connection UUID (none: the default route's) and prints one
  line of JSON: `{status: looked|offline, uuid, name, interface, mdns: listened|not_member|busy, listened, devices: [{mac, ip,
  name, names, vendor, model, kind, services, private_mac}]}`. `mac` is empty for a device heard but not in the neighbour
  table. It sends nothing and writes nothing.
- **Who:** Yggdrasil Settings (device page; the integration file's `devices_scan`, `devices_kind` and `devices_look`).
- **Where:** `rust/heimdall/src/cli/lan/`, `api.rs`. [DEVICES.md](DEVICES.md).

## Wi-Fi checks: `heimdalld wifi-health --json`

- **What:** `heimdalld wifi-health --json [--speed]` prints `connected`, `summary`, `verdict` (good|warn|bad), `link`
  {ssid, band, channel, width, signal_dbm, rx_mbps, tx_mbps}, `findings` [{check, status good|info|warn|bad, title,
  detail}], `speed` {down_mbps, server, error}. [WIFI_HEALTH.md](WIFI_HEALTH.md).
- **Who:** Yggdrasil Settings (the integration file's `wifi_check`).
- **Where:** `rust/heimdall/src/cli/wifihealth.rs`.

## Wi-Fi trust: `heimdall-wifi-guard`, `wifi-trusted.json`, `state.json`

- **What:** `/etc/heimdall/wifi-trusted.json` holds the trusted networks; an entry may carry `kind` (`mesh`,
  `phone-hotspot`, `travel`, `other`; absent or unknown means `home-router`) and `"discoverable": true`; a network that is
  not trusted but discoverable is `{"ssid", "level": "untrusted", "discoverable": true}`, which every reader counts as
  untrusted. Commands Settings runs: `pkexec /usr/bin/heimdall-wifi-guard trust [--home] [--real-address] --uuid UUID`,
  `pkexec /usr/bin/heimdall-wifi-guard untrust UUID`, `heimdall-wifi-guard kind [--uuid UUID]` (prints `NAME: kind KIND`)
  and `pkexec ... kind KIND --uuid UUID`, `heimdall-wifi-guard discoverable --uuid UUID` (prints `NAME: discoverable
  on|on (home)|off`), changed by starting `heimdall-wifi-discoverable-on@UUID.service` / `-off@UUID.service` over systemd's
  D-Bus (polkit's own default, the administrator's password). `/run/heimdall-wifi-guard/state.json` says whether a trusted
  network counts as trusted this time and which `protections` are on (`discoverable` among them).
  [WIFI_TRUST.md](WIFI_TRUST.md).
- **Who:** Yggdrasil Settings (`packages/settings/src/wifitrust.rs`), the device list (reads the levels).
- **Where:** `rust/heimdall/src/cli/wifitools/guard.rs`; the Python programs in `packaging/net/` (the fallback).

## Several connections at once: `heimdall-multilink`

- **What:** `heimdall-multilink status --json` (the service's `/run/heimdall-multilink/status.json` while it runs: `state`
  active|paused|waiting, `reason`, `since`, `new_links`, `combined_rate`, `links[]` with `name role up ipv4 ipv6 healthy4
  healthy6 weight4 weight6 rtt_ms rate peak share_now share_limit data_cap_mb period used_bytes over_cap`; rates in bytes/s;
  while the service is off the command prints the same shape with `state` "off" and only `name role up ipv4 ipv6
  share_limit data_cap_mb period` per link). Changes:
  `pkexec /usr/bin/heimdall-multilink on|off|set LINK use|backup|off [--share N|none] [--cap MB|none] [--per day|month]|new-links
  ROLE`. [MULTILINK.md](MULTILINK.md).
- **Who:** Yggdrasil Settings > Wi-Fi & Network > Several connections at once.
- **Where:** `rust/multilink` (`src/service.rs`, `status_json`).

## Safe file intake: `heimdall-fileguard scan|extract --json`

- **What:** `heimdall-fileguard scan --json FILE...` prints `{"files":[{"path","verdict":"ok"|"warn"|"refused","reasons":[...],
  "clamav":"clean"|"infected:SIG"|"unavailable"|"not-fully-scanned"}]}`; `heimdall-fileguard extract --json [--only EXT,EXT]
  ARCHIVE OUTDIR` prints `{"files":[{"name","path","size","verdict","reasons","clamav"}],"skipped":[{"name","reason"}],
  "refused":null|"..."}`. Exit 0 nothing refused, 1 refused, 2 usage or reading error. OUTDIR must not exist; on a refusal
  nothing is left. [PRIVACY_PACK.md](PRIVACY_PACK.md), section 5.
- **Who:** Yggdrasil Settings (fonts page; `packages/settings/src/fontlib.rs`).
- **Where:** `rust/privacy`.

## The privacy pack's switches and `heimdall-strip`

- **What:** `~/.config/heimdall/privacy.json` `{"downloads_guard","remove_hidden_info","lookalike_warnings","folders_guard"}`,
  each missing = on; Settings writes it and the guard follows it live. `heimdall-strip --can IN` and `heimdall-strip --json
  IN OUT` (`{"wrote","removed","kind"}`; exit 0/1/2; never over a file). [PRIVACY_PACK.md](PRIVACY_PACK.md).
- **Who:** Yggdrasil Settings > Security > Privacy (the switches), Minos (Remove hidden info), Settings > Apps and Agora
  (look-alike warnings).
- **Where:** `rust/privacy`.

## The private microphone, the scrub and the voice disguise

- **What:** `heimdall-private-mic status --json` (`{"enforce","node","lykanos","sarina_raw","disguise","disguise_preset"}`:
  booleans, the preset `"lower"|"higher"`), `on|off`, `disguise on|off|lower|higher`, `sarina-raw on|off` (exit 1 off
  LykanOS); the voice input marked `heimdall.private-mic.exempt = "sarina-voice"` is the only stream `sarina-raw` lets
  through, on LykanOS only; `heimdall-scrub --progress IN OUT` (`progress 0.42` lines, then exactly `wrote OUT`; exit 0/1/2; never over IN
  or an existing OUT); `heimdall-scrub --disguise PRESET IN OUT`. [LOCATION_SOUNDS.md](LOCATION_SOUNDS.md),
  [VOICE_DISGUISE.md](VOICE_DISGUISE.md).
- **Who:** Yggdrasil Settings (Privacy, Peripherals > Microphone), Minos, the panel's Super+S recording; Sarina records the
  private microphone like every app.
- **Where:** `rust/scrub`, `rust/scrub-ladspa`, `packaging/privacy/`.

## What an OS sets for Heimdall: `defaults-off`, `security-tools`

- **What:** `/etc/heimdall/defaults-off` makes the install hook (`heimdall-enable-defaults`) leave Heimdall off
  (`--force` switches it on anyway); `/etc/heimdall/security-tools` lists the security tools whose activity the tool rules
  summarise instead of alerting on. [TOOL_RULES.md](TOOL_RULES.md), [STANDALONE.md](STANDALONE.md).
- **Who:** LykanOS ships both; Labyrinth OS's first boot and LykanOS's image build run `heimdall-enable-defaults` (paths,
  output and exit codes stable).
- **Where:** `rust/heimdall/src/cli/shtools.rs` (enable-defaults), `toolrules.rs`.

## Mesh (Heimdall to Heimdall)

- **What:** peers POST `/mesh/v1/alerts` over mutual TLS 1.3 (enrolled ed25519 keys only) on `mesh_listen` (port 8931, on
  my own WireGuard or LAN address, never a wildcard). Off by default. [MESH.md](MESH.md).
- **Who:** Heimdall on my other computers.
- **Where:** `rust/heimdall/src/mesh.rs`, `cli/mesh.rs`.
