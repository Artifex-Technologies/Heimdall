# External references

Every project cited as a design or technique reference for
Heimdall, tracked in one place so an update to any of them can be checked
against what this repo actually did with it. `docs/ARCHITECTURE.md` tells
the design story per phase; this file is the flat ledger underneath it —
one row per reference, pinned to what was actually verified and when, so
"did anything upstream change that matters" has a concrete starting point
instead of a re-read of the whole roadmap.

**None of this code is vendored or copied wholesale.** Every reference
below is in a different language, a different domain, or both — what
transfers is a technique or an architectural shape, translated into
Go/Python and adapted to what this project actually needs. Where that
translation is real (an algorithm, a data format, a specific efficiency
trick), the row says exactly which file has it. Where a reference is
cited for a pattern or a naming decision rather than a concrete technique,
the row says that too, plainly, rather than implying more borrowing than
happened.

## How to use this when a reference updates

1. Check the reference's own recent history (releases, changelog, or just
   `git log` on a local clone) against the **Checked** date below.
2. If something material changed in the area this row cites, read the
   **Where** column and decide whether Heimdall's adaptation needs to
   change too — most rows are a one-time technique borrow, not a live
   dependency, so most upstream changes need no action here at all.
3. Update the **Checked** date and add a one-line note in the row (or in
   `progress.md`, if it drove an actual code change) rather than silently
   moving on — the point of this file is that "checked, no action needed"
   is itself worth recording.

## Status key

| Status | Meaning |
| --- | --- |
| **Adapted** | A concrete technique, algorithm, or data format was translated into this repo's code. |
| **Design reference** | Informed an architectural or naming decision; no line of code corresponds to it directly. |
| **Candidate** | Not used yet; a specific, plausible future adaptation is sketched below. |
| **Methodology-only** | Cited for a transferable *technique*, explicitly not for its actual domain (the genomics entries). |

## Ledger

| Repo | Category | Status | Where | Checked |
| --- | --- | --- | --- | --- |
| [crowdsecurity/crowdsec](https://github.com/crowdsecurity/crowdsec) | Detection engine | Adapted | `internal/detect` (Source→Detector→Sink shape), `internal/detect/burst.go` (leaky bucket). Unused, planned: scenarios as data, expiring decisions, own-mesh signal sharing (R10, R7, R12 in Labyrinth_OS docs/REFERENCE_PLAN_2026-11.md) | 2026-11-17 |
| [zeek/zeek](https://github.com/zeek/zeek) | Network monitoring | Adapted (framing) | `internal/sources/netsource` (connection state, not packet capture). Unused, planned: names beside addresses, intel match at sight (R11) | 2026-11-17 |
| [wazuh/wazuh](https://github.com/wazuh/wazuh) | Host FIM/XDR | Adapted | `internal/sources/hostsource/fim.go` (mtime+size precheck before hashing). Unused, planned: checks as data (SCA), cross-view check (R13) | 2026-11-17 |
| [netdata/netdata](https://github.com/netdata/netdata) | Host telemetry | Adapted (design) | `internal/sources/hostsource/telemetry.go` (`/proc`-only, no fork/exec). Unused, planned: alarm hysteresis (R14) | 2026-11-17 |
| [tailscale/tailscale](https://github.com/tailscale/tailscale) | Secure mesh / Go precedent | Adapted (language choice) + Design reference (mesh) | `README.md` (why Go); `docs/MESH.md` (identity pinning, and the parts deliberately left out after the 2026-10 "Tailworm" flaws) | 2026-11-05 |
| [juanfont/headscale](https://github.com/juanfont/headscale) | Self-hosted mesh control plane | Design reference | Phase 3 mesh (`internal/mesh`): the "your own control" idea, taken further: no control server at all, peers enrolled by the owner | 2026-11-05 |
| [CrowdStrike/codestrike](https://github.com/CrowdStrike/codestrike) | LLM review bot (not the CrowdStrike EDR product) | Design reference | Phase 4 approval-gate framing. Unused, planned: a local second look at update build scripts (R17) | 2026-11-17 |
| [paperclipai/paperclip](https://github.com/paperclipai/paperclip) | AI-agent fleet governance | Design reference | Phase 4 approval-gate framing. Unused, planned: per-agent budgets (R16) | 2026-11-17 |
| [SenteLabsAI/OpenExecutive](https://github.com/SenteLabsAI/OpenExecutive) | Multi-agent-behind-one-voice | Design reference | Phase 4 approval-gate framing | 2026-09-25 |
| [n8n-io/n8n](https://github.com/n8n-io/n8n) | Workflow automation | Candidate | Not built — response playbooks, merged with the Fusion/Foundry rows below (R7) | 2026-11-17 |
| [letta-ai/letta](https://github.com/letta-ai/letta) | Stateful agent memory | Candidate | Not built — see note below (Phase 5 baseline memory) | 2026-09-26 |
| [microsoft/graphrag](https://github.com/microsoft/graphrag) | Graph-based correlation | Adapted (idea, no code) | `internal/correlate`: alerts linked by the entities they share into incidents | 2026-11-05 |
| [onnx/onnx](https://github.com/onnx/onnx) | ML model format | Design reference | Formalizes the format Sarina's own `sarina/ml/` already runs on | 2026-09-26 |
| [tensorflow/tensorflow](https://github.com/tensorflow/tensorflow) | ML framework | Design reference (explicitly not to vendor) | Phase 5 — see Sarina's own onnxruntime-not-TensorFlow precedent | 2026-09-25 |
| [google/deepvariant](https://github.com/google/deepvariant) | Genomic variant calling | Methodology-only | Phase 5 — "sequence → fixed-shape representation → small model scores it" | 2026-09-25 |
| [mortazavilab/TALON](https://github.com/mortazavilab/TALON) | Long-read transcript classification | Methodology-only | Phase 5 — see note below (known/novel-variant/novel classification); also the agent baseline's never-used-before tool. Unused, planned: the "close variant" class, tool-call sequences (R15) | 2026-11-17 |
| [lizTheDeveloper/flyover-scrub](https://github.com/lizTheDeveloper/flyover-scrub) (MIT) | Audio location privacy | Adapted (rewritten in Rust; read, not run) | `rust/scrub` (scrub.py, enf.py), `rust/flyover-attack` (attack.py, trace.py, physics.py); notice `rust/scrub/NOTICE`; `docs/LOCATION_SOUNDS.md` | 2026-11-15 |
| [CrowdStrike/fusion-skills](https://github.com/CrowdStrike/fusion-skills) (MIT) | Workflow authoring (Falcon Fusion) | Design reference | Response playbooks: trigger / condition / action from a fixed verb list, replay test, owner approval (R7). Falcon itself is not used | 2026-11-17 |
| [CrowdStrike/foundry-skills](https://github.com/CrowdStrike/foundry-skills) (MIT) | App packaging (Falcon Foundry) | Design reference | A playbook ships with its own permissions; Sarina may draft, root tests, the owner approves (R7) | 2026-11-17 |
| [VirusTotal/yara](https://github.com/VirusTotal/yara) (BSD-3) | Pattern rules | Adapted (format, through ClamAV) | `immunity` rule drafts loaded by ClamAV (`IMMUNITY.md`); YARA in Limbo's analysis image. **Maintenance mode upstream**: fixes only, new work in YARA-X | 2026-11-17 |
| [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) (BSD-3, Rust) | Pattern rules (successor) | Dependency (crate `yara-x` =1.23.0, my decision 2026-11-18) | `rust/yara-check` (`heimdall-yara-check`, own package): the exact compile check and slow-pattern warnings of rule drafts; the lint's "slow pattern" and "common string" warnings follow its atom rules (`IMMUNITY.md`, "Checking a draft"). `yr` for Limbo's image waits on an official Arch package (AUR only) | 2026-11-18 |
| [abusech/URLhaus](https://github.com/abusech/URLhaus) (data: [abuse.ch terms of use](https://abuse.ch/terms-of-use/), see note below) | Malware URL feed | Adapted (data, via malware-filter) + Adapted (data, own key) + Candidate | `packaging/net/heimdall-dns-blocklist` (URLhaus hosts filter, via malware-filter). ClamAV URL signatures (`urlhaus_clamav.ndb`, `https://urlhaus-api.abuse.ch/v2/files/exports/<key>/urlhaus_clamav.ndb`) through `heimdall-intel-update` into `/var/lib/clamav/heimdall-urlhaus.ndb` (`IMMUNITY.md`, "URLhaus"). Candidate: downloaded hash lists; per-hash API questions never by default (R5) | 2026-11-18 |
| [Suryesh/OTX_AlienVault_URL](https://github.com/Suryesh/OTX_AlienVault_URL) (MIT) | AlienVault OTX client | Candidate | Optional OTX feed, pull-only: subscribed indicator lists into `intel`, never a question about what this computer saw (R6) | 2026-11-17 |
| [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) (MITRE ATT&CK terms of use, `NOTICE-ATTACK`) | Technique catalogue | Adapted (data, trimmed) | Pinned: release **v20.1** (ATT&CK Enterprise 20.1, published 2026-11-05), `enterprise-attack.json` SHA-256 `539a843a…910b5`. `internal/attack/enterprise.tsv` (511 Linux/Windows techniques: ID, name, tactics), written by `rust/tools/attack-table`; detector → technique tags on alerts, `internal/attack/tags.tsv` (R1 phases 1-2). Regenerate: `docs/ATTACK.md`, "A new ATT&CK release". The bundle is not committed | 2026-11-18 |
| [mitre-attack/mitreattack-python](https://github.com/mitre-attack/mitreattack-python) (Apache-2.0) | ATT&CK tooling | Candidate (idea only) | `heimdalld attack-layer`: a Navigator layer and a gap list of what the detectors watch (R2) | 2026-11-17 |
| [bauerj/mac_vendor_lookup](https://github.com/bauerj/mac_vendor_lookup) (Apache-2.0) | MAC vendor lookup | Design reference | The offline half: `rust/macvendor` (crate `heimdall-macvendor`) and its Go twin `internal/macvendor`. The refresh with a kept last-good copy is designed (`docs/DEVICES.md`, "Vendor data"), not built: my decision on downloading (R3) | 2026-11-17 |
| [Ringmast4r/OUI-Master-Database](https://github.com/Ringmast4r/OUI-Master-Database) (no licence) | MAC vendor data | Design reference (ideas only) | Built: all IEEE registries (MA-L, MA-M, MA-S, IAB), longest-prefix match, a shared crate (`rust/macvendor`, R3). Designed, not built: the monthly refresh. Its merged data is **not** used (mixed licences) | 2026-11-17 |
| [IEEE Registration Authority](https://standards.ieee.org/products-programs/regauth/) public listings (MA-L, MA-M, MA-S, IAB) | MAC vendor data | Adapted (data, read offline; nothing of it in this repo) | Read by `rust/macvendor` and `internal/macvendor` from Arch's hwdata package (`oui.txt`, `iab.txt`) and, once downloaded, the IEEE's own CSV files in `/var/lib/heimdall-ieee`. The IEEE publishes them for anyone to download; no other project's list is read (`docs/DEVICES.md`, "Vendor data") | 2026-11-17 |
| [feross/SpoofMAC](https://github.com/feross/SpoofMAC) | MAC address change | Design reference | `packaging/net/heimdall-wifi-privacy.conf`, `heimdall-wifi-guard` (stable random address per untrusted network). Planned: wired networks, IPv6 privacy, Bluetooth check (R19) | 2026-11-17 |
| [claffin/cloudproxy](https://github.com/claffin/cloudproxy) (MIT) | Throwaway egress | Candidate (Limbo) | Limbo analysis network: sinkhole first, then a per-run tunnel so the home address is never seen (R8); `limbo-network` alerts keep covering it | 2026-11-17 |
| [NationalSecurityAgency/datawave](https://github.com/NationalSecurityAgency/datawave) (Apache-2.0) | Labelled data access | Candidate (idea only) | Per-record visibility labels on alerts and evidence, checked at read time in `api.rs` (R9) | 2026-11-17 |
| [storytold/realtime-voice-conversion](https://github.com/storytold/realtime-voice-conversion) (no licence) | Real-time voice conversion | Candidate (idea only) | Private mic: "disguise my voice", DSP first, synthetic voices only, never a real person's (R18) | 2026-11-17 |

## Notes on the newer or less obvious entries

**juanfont/headscale reopens Phase 3's mesh half.** That section of
`docs/ARCHITECTURE.md` marked cross-machine alert sharing "not currently
planned," specifically because CrowdSec's own central-API model raises a
trust question this project was never asked to solve — whose server, what
data leaves the machine. Headscale is a self-hosted, open-source
implementation of Tailscale's own control server: the same mesh mechanics
Tailscale already justified the language choice with, but with the
"whose server" question answered by "yours." This doesn't move the mesh
half to *built*, but it removes the specific objection that kept it out of
the plan — worth a real design pass before the next time Phase 3 comes up,
not just a citation.

**n8n's node/trigger/workflow model, as a response-playbook idea.** Not
Heimdall watching workflows — the transferable shape is "when X is detected,
run this sequence of steps," which is a plausible future extension of
Phase 4's governance layer: today `/v1/review` only answers yes/no; a
playbook layer could take an action (notify, quarantine a file, restart a
watcher) in response to a specific finding. A design was written on
2026-11-17 (R7 in Labyrinth_OS's `docs/REFERENCE_PLAN_2026-11.md`); still a candidate until built.

**letta-ai/letta's persistent, self-editing agent memory, for Phase 5.**
The transferable idea is tiered memory (a small, always-in-context working
set vs. a larger archival store), applied to Heimdall's *own* alert history
rather than an LLM's context window — Phase 5's sketch already wants to
catch "a slow drift in tool-call mix, not any single bad message," which
needs some notion of recent-vs-longer-term baseline. How much of Letta's
actual architecture (vs. just the tiering idea) is worth borrowing is
still open.

**microsoft/graphrag's graph construction, for cross-alert correlation.**
Not the LLM-retrieval half of GraphRAG — the transferable piece is
building a graph out of Heimdall's own alert stream (nodes: sessions,
sessions, ports, files; edges: "this session triggered this alert near
this other alert") and applying graph/community-detection techniques to
surface a multi-stage pattern no single detector would catch alone (e.g. a
governance denial, a burst, and a network exposure event from the same
session within a short window). Worth noting GraphRAG itself is in
maintenance mode upstream (bug fixes only) — the technique is still valid
to borrow, but this specific repo is not a moving target to keep
re-checking.

**mortazavilab/TALON's known/novel classification, for Phase 5.** Flagged
by the user as genomics-for-pattern-recognition-only, not literal reuse.
TALON matches a sequencing read against known transcript models by its
splice-junction signature, classifying it as a known model or a genuinely
novel one. The transferable shape for Phase 5: classify an observed
sequence of events (a session's tool-call pattern) against known-benign
reference patterns the same three-way way — a known match, a close variant
of one, or something with no match at all — rather than Phase 1-4's
binary allow/deny detectors.

**google/deepvariant's pileup-image framing, for Phase 5.** Already in
`docs/ARCHITECTURE.md`: the transferable idea is turning a *sequence* of
discrete reads into a fixed-shape representation a small model scores,
not genomics itself. Recorded here too since it's the other genomics
reference the user flagged as pattern-recognition-only.

**ipinfo/cli (Apache-2.0), for where an attack comes from.** The owner's reference for naming the
source of an attack so an address can be blocked. Taken as an idea only: the CLI queries
IPinfo's servers, which would send every address Heimdall sees off the machine. What is kept is
the offline half: IPinfo (and DB-IP) publish free databases in the MaxMind DB format, which
`internal/ipintel` reads directly. `grepip`-style extraction became `fwsource`'s journal parsing.

**The 2026-11-17 review.** I went through 26 starred projects; the R numbers in the rows above are the work items in
Labyrinth_OS's `docs/REFERENCE_PLAN_2026-11.md`, which says per item what exists, the phases and the open decisions. All are
references: nothing is installed or copied, each idea is rewritten in Rust. Rows for projects that only concern Sarina or
the desktop are kept in those repositories, not here.

**YARA is in maintenance mode; YARA-X is its successor.** VirusTotal's C YARA now gets bug fixes only, and new syntax and
modules land in YARA-X (Rust, same BSD-3 licence, declared stable). Heimdall's rules are installed for ClamAV, which loads a
YARA subset of its own, so nothing breaks today. What changes: draft checks should warn about what YARA-X warns about
(short or common strings make slow rules), and Limbo's analysis image should move to YARA-X's `yr` when its package is
ready. Using the `yara-x` crate inside Heimdall would be a dependency, not copied code; that is an owner decision.
I decided yes on 2026-11-18: the crate is a dependency of `heimdall-yara-check` only (its own workspace, lock file and
package; not of the daemon), with its BSD-3 notice in `rust/yara-check/NOTICE`. `cargo audit` checks its lock file in CI;
the one advisory ignored there is RUSTSEC-2025-0141 (bincode unmaintained, no vulnerability; yara-x uses it only to save and
load compiled rules, which the checker never does).

**ATT&CK data carries MITRE's notice.** The trimmed table landed on 2026-11-18 (I approved it that day): it is committed with
MITRE's copyright line and terms of use verbatim in `NOTICE-ATTACK` (installed beside the licence), and its disclaimer holds
here too: a tag says what a detector looks for, never that a technique is covered. The reasons per tag and the gap list are
in `docs/ATTACK.md`.

**URLhaus's licence, checked 2026-11-18.** It is no longer plain CC0 from abuse.ch itself. Its
[terms of use](https://abuse.ch/terms-of-use/) say "Access to the abuse.ch Platforms is provided only to: Users who have
completed the authentication process" and that "Authenticated Users may access the Platforms for not-for-profit purposes";
for MalwareBazaar, URLhaus and ThreatFox, commercial use "may require a paid subscription, which will be managed by Spamhaus".
The sentence "free to use without limitations according to Creative Commons principles (CC0)" now covers only Feodo Tracker,
SSL Blacklist and YARAify. The keyless downloads (`urlhaus.abuse.ch/downloads/urlhaus.ndb` and the other `/downloads/` files)
answer 410 Gone; the exports need an Auth-Key in the address's path. So the ClamAV signatures run on my own free key, for
not-for-profit use, and each computer that wants them needs its owner's key; nothing of them is shipped in the package.
[malware-filter's urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter) (the DNS list's source) still states
"URLhaus: CC0" and "This repository is not endorsed by Abuse.ch"; it publishes no ClamAV file.
