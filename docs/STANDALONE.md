# Heimdall without Sarina

Sarina is optional on Labyrinth OS (an Agora download), and Niflheim OS may not ship her at all. This page says what Heimdall does
on a computer without her, what used to be missing, and what still needs her. Written 2026-10-25 from every place the code mentions
Sarina (`grep -rni sarina`, about 170 lines in 30 files).

## Short answer

Most of Heimdall never needed Sarina: it watches the computer itself. What was missing was small but visible: the daemon refused to
start unless an AI agent's session folder (or Limbo's log) was configured, a missing Sarina showed up as alerts, and alerts had no
plain-language explanation unless Sarina gave one. Those are fixed (see "What was built"). With Sarina installed, nothing changes:
her advice comes in addition to Heimdall's own words.

## Every touchpoint, grouped

### (a) Detection that reads Sarina

| Where | Without Sarina |
| --- | --- |
| `sources/agentsource` (her `.port_sessions` / `/var/lib/sarina/sessions`) | Nothing to read. Used to raise `agent_session_unreadable` once at start; now quiet while she is not installed, and reading starts by itself if she is installed later (the folder appears). |
| `detect/injection`, `credential`, `unicode`, `escalation`, `burst` | Fed by agentsource and Limbo. Idle without an agent; still used by `POST /v1/review` and on Limbo guests. |
| `trust` (signed list of the AI agents' behaviour files) | Mode `off` by default; with no agent there is nothing to sign. The file watch for Heimdall's own config still works. |
| `config.NetPorts` (8899 Sarina, 8765 Sarina's Telegram, 11434 Ollama, 8930 Heimdall) | Ports nobody listens on are simply never exposed: no alert, no cost. |
| `config.FIMPaths` (`/usr/bin/sarina`, her units) | A watched path that does not exist is skipped by the file watch (no alert); it starts being watched once installed. |

Nothing else in detection touches her. Everything that watches the computer works alone: file integrity of system programs and
settings, open ports and connections (with origin and threat lists), the firewall and SSH logins, packages and kernels against
security trackers, hardening settings, Wi-Fi and LAN impersonation, memory and load pressure and drift, malware scanning with ClamAV,
immunity (holding unknown files, fingerprints), and Limbo sandboxes.

Could agentsource watch something else? Only an agent that writes session files in the same format; no other local agent on
Labyrinth does today. If one appears, `agent_session_dir` can point at it; until then the source is simply off.

### (b) Explanations and advice

| Where | Before | Now |
| --- | --- | --- |
| `response.Sarina` (advice on each new Limbo quarantine) | Asked whenever `sarina_url` was set; with her absent every quarantine also raised `sarina_unreachable`. | Wrapped in `response.IfInstalled`: asked only while `sarina_installed` exists, checked at each call; absent means no advice and no alert. |
| Alert text | Each detector's one-line summary; the "what to do" was often missing, and Sarina's security topic was the explanation. | Every alert carries `explain` (package `explain`): what happened, how serious, what Heimdall already did, what to do, from fixed text per detector and severity. No AI, same every time, observed values quoted and cleaned. |
| Quarantine record in Limbo | Sarina's advisory only. | Heimdall's own explanation is attached to every new quarantine (source `heimdall`); Sarina's is added beside it when she is there. |
| `immunity` notices (held file, analysis done) | Said "Sarina can look at it with you" / "Sarina's next review uses it". | Those sentences are added only when she is installed. (`hardening` mentions her only in a code comment.) |

### (c) The owner in the loop

All of this already worked without Sarina, through the desktop's `security` integration (Yggdrasil `docs/INTEGRATIONS.md`):

- Alerts become desktop notifications: the panel polls `GET /v1/alerts` (warning and critical by default, Settings > Notifications).
  Now the notification also says "What to do: ..." from `explain`.
- Settings > Security lists recent alerts, held files (Release / Keep as malware, `held_release` / `held_confirm`), the quarantine
  (Restore / Delete), connections, the malware scan, containment release. Now each alert has an Explain button showing the four parts.
- Heimdall's own root notices (held files, Limbo analysis done, containment) reach every signed-in desktop through
  `contain.Real.Notify` (notify-send as that user, on their session bus); no Sarina involved.
- The requests spool (`/var/lib/heimdall-requests`, release-if-proven) is used by Sarina and by the check-up; the owner releases from
  Settings instead, which needs no spool.
- Immunity analyses (Limbo takes a held file apart) are stored with the held file and shown in Settings.

### (d) Containment

`heimdalld contain` stops a compromised AI agent: unload the models (Ollama), stop and lock Sarina's units and processes, keep
evidence. Without Sarina the Sarina steps find nothing (their errors are ignored) and the model unloading still applies to anything
using Ollama. Automatic containment is triggered only by critical findings about the AI agents, which do not occur without one.

### (e) Errors and noise when Sarina is absent

| Was | Now |
| --- | --- |
| `heimdalld run` exited 2 without `agent_session_dir` or `limbo_event_log` ("nothing to watch") although it watches much more. | Starts and logs "watching the computer itself". |
| A missing session folder: a log line and an `agent_session_unreadable` alert. | Quiet while Sarina is not installed; still reported if she is installed and the folder is wrong. |
| `sarina_unreachable` on every quarantine. | Not asked while she is not installed. |
| Logs once at start: | "Sarina is not installed: running on my own (alerts are explained with built-in text)". |

`heimdalld scan` (the one-shot audit) still requires a session folder or Limbo log: an audit that read nothing must not look clean.

## What was built (2026-10-25)

- `internal/explain`: plain-language explanation for every detector, at every severity, plus a general fallback; tested that none is
  empty and that observed values (paths, names) are quoted, one line, cut short.
- `alert.Alert.Explain` (JSON `explain`): set by `FromFinding` and `Integration`, so the API, the log and the desktop all have it.
- `response.IfInstalled` and Heimdall's own advisory on each new Limbo quarantine.
- `config.SarinaInstalled` (`sarina_installed`, default `/usr/bin/sarina`): the one place that says whether she is there.
- `heimdalld run` starts without agent or Limbo sources; quiet about a Sarina that is not installed.
- Yggdrasil: Settings > Security shows each alert's explanation (Explain button); the panel's alert notifications add "What to do".

## What still needs Sarina

- Conversation: asking "is this safe?", follow-up questions, explanations tailored to the exact case.
- Advice that reads the evidence (her advisory on a quarantine reads the guest's output; Heimdall's own text is generic per kind).
- Releasing a held file by proof through the requests spool on her own initiative (the owner can always release in Settings).
- Watching an AI agent's sessions: there is no agent to watch.

Security invariants are unchanged: Heimdall can only restrict more (no release route on Limbo's socket), releases need the owner, and
neither Heimdall's text nor any advice is ever followed as an instruction.
