# External references

Every project cited as a design or technique reference for Chymaera
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
| [crowdsecurity/crowdsec](https://github.com/crowdsecurity/crowdsec) | Detection engine | Adapted | `internal/detect` (Source→Detector→Sink shape), `internal/detect/burst.go` (leaky bucket) | 2026-09-25 |
| [zeek/zeek](https://github.com/zeek/zeek) | Network monitoring | Adapted (framing) | `internal/sources/netsource` (connection state, not packet capture) | 2026-09-26 |
| [wazuh/wazuh](https://github.com/wazuh/wazuh) | Host FIM/XDR | Adapted | `internal/sources/hostsource/fim.go` (mtime+size precheck before hashing) | 2026-09-26 |
| [netdata/netdata](https://github.com/netdata/netdata) | Host telemetry | Adapted (design) | `internal/sources/hostsource/telemetry.go` (`/proc`-only, no fork/exec) | 2026-09-26 |
| [tailscale/tailscale](https://github.com/tailscale/tailscale) | Secure mesh / Go precedent | Adapted (language choice) + Candidate (mesh) | `README.md` (why Go); Phase 3 mesh, not built | 2026-09-25 |
| [juanfont/headscale](https://github.com/juanfont/headscale) | Self-hosted mesh control plane | Candidate | Phase 3 mesh — see note below, changes that phase's status | 2026-09-26 |
| [CrowdStrike/codestrike](https://github.com/CrowdStrike/codestrike) | LLM review bot (not the CrowdStrike EDR product) | Design reference | Phase 4 approval-gate framing | 2026-09-25 |
| [paperclipai/paperclip](https://github.com/paperclipai/paperclip) | AI-agent fleet governance | Design reference | Phase 4 approval-gate framing | 2026-09-25 |
| [SenteLabsAI/OpenExecutive](https://github.com/SenteLabsAI/OpenExecutive) | Multi-agent-behind-one-voice | Design reference | Phase 4 approval-gate framing | 2026-09-25 |
| [n8n-io/n8n](https://github.com/n8n-io/n8n) | Workflow automation | Candidate | Not built — see note below (response-playbook idea) | 2026-09-26 |
| [letta-ai/letta](https://github.com/letta-ai/letta) | Stateful agent memory | Candidate | Not built — see note below (Phase 5 baseline memory) | 2026-09-26 |
| [microsoft/graphrag](https://github.com/microsoft/graphrag) | Graph-based correlation | Candidate | Not built — see note below (Phase 5 cross-alert correlation) | 2026-09-26 |
| [onnx/onnx](https://github.com/onnx/onnx) | ML model format | Design reference | Formalizes the format Sarina's own `sarina/ml/` already runs on | 2026-09-26 |
| [tensorflow/tensorflow](https://github.com/tensorflow/tensorflow) | ML framework | Design reference (explicitly not to vendor) | Phase 5 — see Sarina's own onnxruntime-not-TensorFlow precedent | 2026-09-25 |
| [google/deepvariant](https://github.com/google/deepvariant) | Genomic variant calling | Methodology-only | Phase 5 — "sequence → fixed-shape representation → small model scores it" | 2026-09-25 |
| [mortazavilab/TALON](https://github.com/mortazavilab/TALON) | Long-read transcript classification | Methodology-only | Phase 5 — see note below (known/novel-variant/novel classification) | 2026-09-26 |

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
watcher) in response to a specific finding. No design has been written for
this yet — it's a candidate, not a plan.

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
