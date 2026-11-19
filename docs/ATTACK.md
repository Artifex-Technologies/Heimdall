# ATT&CK technique tags

Heimdall's alerts name, in MITRE ATT&CK's words, what the detector that raised them looks for. An alert from the LAN
watch about the router's hardware address changing carries `"attack": ["T1557.002"]`, and its explanation says
"Adversary-in-the-Middle: ARP Cache Poisoning". Item R1 of my reference plan (in my private
plans: Labyrinth_OS docs/plans/REFERENCE_PLAN_2026-11.md), phases 1 and 2; I approved shipping the table on 2026-11-18.

**A tag says what a detector watches. It never says a technique is covered**, that Heimdall would catch every use of it, or
that an alert proves an attack. That is MITRE's own warning (NOTICE-ATTACK, "Disclaimers") and my rule: a tag goes on only
where the thing the detector triggers on is the technique's own action or its direct trace. Where the link is looser, the
detector has no tag and the reason is in the gap list below. A gap list is as useful as a coverage list.

## The files

| File | What | Who writes it |
| --- | --- | --- |
| `internal/attack/enterprise.tsv` | the technique table: ID, name, tactics; 511 techniques and sub-techniques of ATT&CK Enterprise 20.1 for Linux or Windows, revoked and deprecated left out; 33 KB | `rust/tools/attack-table`, from MITRE's bundle; never by hand |
| `internal/attack/tags.tsv` | the detector map: detector, event kind, one field condition, technique IDs | by hand, with a reason below for every row |
| `NOTICE-ATTACK` | MITRE's copyright statement and terms of use, verbatim; installed as `/usr/share/licenses/heimdall/NOTICE-ATTACK` | by hand |

Go (`internal/attack`) embeds both files; Rust (`rust/heimdall/src/attack.rs`) compiles in the same two files from the same
paths. Each reads them once, on the first alert, into slices of the compiled-in text (about 30 KB and a small index), so
the daemon stays as light as before on a Raspberry Pi. A sub-technique's name is written as MITRE's site writes it,
"Parent: Sub". Tactics are MITRE's short names (`credential-access`, `defense-impairment`, ...), kept for the coverage map
(R2); the alerts do not carry them.

### The map's rules

- Columns: detector, event kind (`*` any), a condition on one alert field (`*` none; `key=value`; `key=*` means the field
  is there and not empty), technique IDs (comma-separated).
- The first row that matches decides. No matching row: no tags (the field is left out of the alert).
- Every ID must be in the table, or the file does not load (tests in both languages; the daemon would then tag nothing
  rather than fail).
- The field conditions only compare with fixed words, so an observed value (a guest's file name, a network name) can never
  choose a tag of its own.

## What each detector watches

| Detector (kind, field) | Tags | Why |
| --- | --- | --- |
| `file-integrity` (`file_created`, `file_modified`, `file_deleted`) | T1565.001 Data Manipulation: Stored Data Manipulation | It reports exactly that: a watched program or setting file (the AI agents' behaviour files, the security tools) created, changed or deleted outside a package update. I left out T1485 Data Destruction for deletions: one watched file is not the destruction of data at scale. |
| `tool-rules` (any) | T1554 Compromise Host Software Binary | Its own alert is a security tool's program whose SHA-256 differs from what its package installed: a changed host binary. (Its other findings keep their own detector's ID.) |
| `credential-shape` (any) | T1552.001 Unsecured Credentials: Credentials In Files | It reads the agent's session files and vault notes for secrets in plain text, which is what that technique harvests. It does not watch anyone searching for them. |
| `inbound` (`block_command` present) | T1110 Brute Force | The failed-login alert: many failed logins from one address. The parent technique, because guessing, spraying and stuffing look the same from here. |
| `inbound` (`ports` present) | T1046 Network Service Discovery | The port-scan alert: one address trying many ports. ATT&CK files a scan from the internet under Reconnaissance (T1595, platform "PRE", not in my table); T1046 is the same act from inside a network, such as another device on a Wi-Fi network. The "blocked many times" info alert has no tag: the firewall doing its job is not a scan. |
| `lan-watch` (`router_changed`, `router_impersonated`, `lan_device_changed`) | T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning | Each is one device answering for another's address, the trace ARP spoofing leaves. |
| `lan-watch` (`rogue_router`) | T1557 Adversary-in-the-Middle | A second DHCP server, a second IPv6 router, or a trusted network's router fingerprint changing. Only the parent: one alert can be DHCP spoofing (T1557.003) or a rogue IPv6 router, which ATT&CK has no sub-technique for. |
| `lan-watch` (`new_lan_device`) | T1200 Hardware Additions | A device new to a trusted home network. MITRE's detection advice for T1200 is exactly an inventory that notices devices that should not be there; most new devices are a visitor's phone, which the tag does not deny. |
| `remote-access` (`ra_kind=remote-desktop`) | T1219.002 Remote Access Tools: Remote Desktop Software | AnyDesk, TeamViewer, RustDesk, VNC, xrdp found installed, with their interface, or connected. |
| `remote-access` (`ra_kind=rmm`) | T1219 Remote Access Tools | The MeshCentral agent: a remote-management tool, the parent technique. |
| `remote-access` (`ra_kind=tunnel`) | T1572 Protocol Tunneling | ngrok, Cloudflare Tunnel, frp, chisel, rathole, bore, VS Code tunnel. (VS Code's is also T1219.001 IDE Tunneling; one row per kind keeps the map simple.) |
| `remote-access` (`ra_kind=anonymizer`) | T1090.003 Proxy: Multi-hop Proxy | Tor, ATT&CK's own example for that technique. |
| `remote-access` (`remote_access`, `signal=tunnel`) | T1572 Protocol Tunneling | A tunnel interface no catalog tool explains. |
| `limbo-guest` (`guest.start`, `policy.remove`) | T1686 Disable or Modify System Firewall | A guest started with no firewall policy loaded first, or its policy removed while it runs. (ATT&CK 20 moved this from T1562.004 to T1686.) `image.rejected` and `gate.blocked` have no tag. |
| `limbo-network` (`net.anomaly`, `reason=scan`) | T1046 Network Service Discovery | A guest refused many destinations in a short time. |
| `limbo-exchange` (`exchange.held`) | T1570 Lateral Tool Transfer | A file leaving a guest for this computer matched a virus signature: a tool moving from one system to another. `exchange.fail` (the scanner failed) has no tag. |

The parity fixtures (`testdata/parity`) show the tags on the recorded alerts of every tagged row but `rmm` and `anonymizer`,
in both languages, and `functions.json` checks every row of the map (a match and a near miss) in both.

## Gaps: what is not watched, or not tagged

Detectors with no tag, and why:

| Detector | Why no tag |
| --- | --- |
| `injection-phrase`, `invisible-unicode` | Attacks on an AI agent (prompt injection, hidden instructions). ATT&CK Enterprise has no technique for them; MITRE ATLAS does (AML.T0051 LLM Prompt Injection), and ATLAS is a different data set I have not taken in. |
| `permission-escalation`, `session-burst`, `agent-baseline` | The agent's behaviour against its own permissions and habits. Not ATT&CK privilege escalation (T1068 and others are about the operating system), and not any other technique. |
| `connection-watch` | A connection to an address on a threat list, an app whose network I switched off, an ecosystem program leaving the machine, a new destination. It sees addresses, not how a channel works, so it cannot say which Command and Control technique (T1071, T1573, ...) is in use. |
| `remote-access` with `ra_kind=c2` | Sliver and Merlin code in a program. ATT&CK lists them as Software (Sliver is S0633), not as techniques; my table carries techniques only. |
| `remote-access` with `ra_kind=mesh-vpn` | Tailscale, ZeroTier, NetBird, headscale: a VPN I may run on purpose. No technique fits without overclaiming (T1133 External Remote Services is about an organisation's own VPN gateways). |
| `wifi-safety` | One verdict over many checks (encryption, an evil twin, TLS interception, the firewall, a sign-in page), with the reasons as free text. A tag per verdict would be wrong for most alerts; it needs the check names in a field first. (Evil Twin, T1557.004, is platform "Network Devices" and not in my table anyway.) |
| `lan-watch` `new_listener`, `wifi_inbound` | A program listening, a device reaching for this computer once: neither is a technique by itself. |
| `limbo-network` `host_probe`, `lan_probe`, `ipv6` | A refused packet towards the host or the home network. Probing, but one packet is not service discovery, and the direction alone does not say which lateral-movement technique was meant. |
| `network-exposure` | Sarina's or Heimdall's own port bound beyond loopback: my configuration rule, not an adversary technique. |
| `hardening`, `package-vulnerability`, `kernel-vulnerability` | The state of the system (a setting, a vulnerable version), not an action. Exploitation techniques (T1068, T1203, T1190) would claim an exploit was seen. |
| `resource-pressure`, `baseline-drift` | Load and memory against a threshold or this computer's normal. Resource Hijacking (T1496) shows up this way, but so does any busy evening. |
| `maintenance-window`, `rule-draft`, `grant-request`, `incident`, `integration`, `mesh` | Heimdall's own bookkeeping, or alerts made of other alerts (an incident does not merge its members' tags). |

Whole areas Heimdall does not watch (so no tag could exist): process execution and command lines (T1059 Command and
Scripting Interpreter), scheduled tasks and services as persistence (T1053, T1543), account changes (T1098, T1136),
credential dumping from memory (T1003), log clearing (T1685.005, T1685.006), and everything Windows-only: Heimdall runs on Arch Linux; the Windows rows are in the table for Limbo's Windows guests
(phase 3).

## For Settings and Sarina: the contract

- `GET /v1/alerts` (unchanged access rules): an alert may carry `"attack": ["T1557.002", ...]` (technique IDs, in the map's
  order; left out when none), and its `explain` object may carry `"attack": [{"id": "T1557.002", "name":
  "Adversary-in-the-Middle: ARP Cache Poisoning"}]` (the same IDs, each with its name; left out when none). The same two
  fields are in every line of `/var/lib/heimdall/alerts.jsonl`.
- Settings shows the names from `explain.attack`; there is no separate lookup endpoint, because every alert already brings
  its names. MITRE's page for an ID is `https://attack.mitre.org/techniques/T1557/002/` (the dot becomes a slash); a link
  opens it only when I click it, nothing is fetched.
- Both fields are additive. A client that ignores them is unaffected; a client must not treat a missing field as "safe".
- An ID in an alert written by an older Heimdall may be missing from a newer table (MITRE revokes and moves techniques,
  as with T1562.004 → T1686 in release 20); the name is then left out of `explain.attack`, never guessed.

## A new ATT&CK release

I move to a new release by hand, when I choose to:

```sh
gh release list -R mitre-attack/attack-stix-data -L 3                      # pick the release
gh release download v20.1 -R mitre-attack/attack-stix-data -p enterprise-attack.json -D /tmp/attack
cd rust && cargo run --release -p heimdall-attack-table -- /tmp/attack/enterprise-attack.json 20.1 \
    > ../internal/attack/enterprise.tsv
```

The tool refuses a bundle whose own version is not the one given, a name it cannot put in one field, a sub-technique
without its parent, an ID twice. Then: update the version and count in the tests of both languages
(`internal/attack/attack_test.go`, `rust/heimdall/src/attack.rs`), check every row of `tags.tsv` still means what the table
above says (a revoked ID makes the map fail to load, and the tests say so), `go test ./internal/parity -update` and review
the diff, update NOTICE-ATTACK (release, SHA-256, the copyright years from the table's header, the terms if MITRE changed
them) and the row in `docs/REFERENCES.md`. The bundle itself is never committed (55 MB).

## Not done yet (phase 3 and R2)

- Sarina's explanation of an alert names the technique and links MITRE's page (she reads `explain.attack`).
- Limbo's analysis report tags its triage hints (a sample importing `ptrace`, `CreateRemoteThread`) with candidate IDs,
  marked "suggested": the Windows rows of the table are for that.
- R2: `heimdalld attack-layer` writes an ATT&CK Navigator layer of the map, and a generated coverage page from the same
  two tables above.
