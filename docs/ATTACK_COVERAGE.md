# What Heimdall's detectors watch, by ATT&CK tactic

Generated from `internal/attack/tags.tsv` and `internal/attack/enterprise.tsv` by the test
`the_coverage_page_is_current` (rust/heimdall/src/cli/attacklayer.rs); do not edit it by hand. After a change to either
table: `HEIMDALL_WRITE_DOCS=1 cargo test --lib the_coverage_page_is_current` in rust/heimdall. The reasons for each tag
and the gap list are in [ATTACK.md](ATTACK.md).

**A tag says what a Heimdall detector looks for, never that the technique is covered: it does not mean Heimdall would catch every use of it (docs/ATTACK.md).**

ATT&CK Enterprise 20.1: 14 of its 511 Linux and Windows techniques and sub-techniques are named by a detector. The same map as
an ATT&CK Navigator layer: `heimdalld attack-layer > heimdall-layer.json`, then Navigator's "Open Existing Layer".

## Initial Access

| Technique | Watched by |
| --- | --- |
| T1200 Hardware Additions | `lan-watch (new_lan_device)` |

## Persistence

| Technique | Watched by |
| --- | --- |
| T1554 Compromise Host Software Binary | `tool-rules` |

## Defense Impairment

| Technique | Watched by |
| --- | --- |
| T1686 Disable or Modify System Firewall | `limbo-guest (guest.start)`, `limbo-guest (policy.remove)` |

## Credential Access

| Technique | Watched by |
| --- | --- |
| T1110 Brute Force | `inbound (block_command present)` |
| T1552.001 Unsecured Credentials: Credentials In Files | `credential-shape` |
| T1557 Adversary-in-the-Middle | `lan-watch (rogue_router)` |
| T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning | `lan-watch (router_changed)`, `lan-watch (router_impersonated)`, `lan-watch (lan_device_changed)` |

## Discovery

| Technique | Watched by |
| --- | --- |
| T1046 Network Service Discovery | `inbound (ports present)`, `limbo-network (net.anomaly, reason=scan)` |

## Lateral Movement

| Technique | Watched by |
| --- | --- |
| T1570 Lateral Tool Transfer | `limbo-exchange (exchange.held)` |

## Collection

| Technique | Watched by |
| --- | --- |
| T1557 Adversary-in-the-Middle | `lan-watch (rogue_router)` |
| T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning | `lan-watch (router_changed)`, `lan-watch (router_impersonated)`, `lan-watch (lan_device_changed)` |

## Command and Control

| Technique | Watched by |
| --- | --- |
| T1090.003 Proxy: Multi-hop Proxy | `remote-access (ra_kind=anonymizer)` |
| T1219 Remote Access Tools | `remote-access (ra_kind=rmm)` |
| T1219.002 Remote Access Tools: Remote Desktop Software | `remote-access (ra_kind=remote-desktop)` |
| T1572 Protocol Tunneling | `remote-access (ra_kind=tunnel)`, `remote-access (remote_access, signal=tunnel)` |

## Impact

| Technique | Watched by |
| --- | --- |
| T1565.001 Data Manipulation: Stored Data Manipulation | `file-integrity (file_created)`, `file-integrity (file_modified)`, `file-integrity (file_deleted)` |

## Tactics no detector is tagged with

Execution, Privilege Escalation, Stealth, Exfiltration.
