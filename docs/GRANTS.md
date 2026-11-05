# Grants: the one gate for an AI agent asking for more

An AI agent may ask for more than it has. It may never give it to itself. Heimdall is the one place such a request goes, and
the owner is the only one who answers.

Two kinds of request:

- **Escalation** (a *hand-off*): sending the conversation to a stronger model tier, most of all one off this computer: Claude
  Code (`claude_cli`) or a cloud API (`claude`). The conversation and the text of the files in it leave the machine.
- **Access tier**: a higher tier on Sarina's access ladder (`Sarina/docs/ACCESS_LADDER.md`): 1 file tools, 2 tests after her
  changes, 3 shell commands. Tier 4 (administrator) is an allow list on the operating system and is never set here.

## How it works

1. The agent files a request: `POST /v1/requests` with `{"kind": "escalation", "detail": "claude-cli", "session_id": "...",
   "reason": "..."}` (or `"kind": "access_tier", "detail": "2"`). Heimdall stores it in `/var/lib/heimdall/grant-requests.json`
   with the account that sent it (read from the kernel, see "Who may use the API" in `INTEGRATION-FAILURES.md`) and raises a
   `grant-request` alert (warning) that names the command to answer it. The same request again is counted, not queued twice.
2. The owner decides, as root, at a terminal:

   ```
   heimdalld grant status                      the gate, the cap, approved hand-offs, open requests
   sudo heimdalld grant approve ID [--for 1h]  allow it (a hand-off lasts --for, at most 24 hours; you type yes)
   sudo heimdalld grant deny ID
   sudo heimdalld grant tier N                 set the access tier cap directly (0-3)
   sudo heimdalld grant revoke                 end every approved hand-off now
   sudo heimdalld grant off                    switch the gate off
   ```

3. The answer is written to `/etc/heimdall/grants.json` (root's, mode 0644). The agent reads that file itself. It never takes
   an answer over HTTP, because while Heimdall is stopped another program could take its port and answer "approved".

The gate is **on while `/etc/heimdall/grants.json` exists** (`grant tier N` creates it). While it is on, Sarina:

- uses the lower of her own tier setting (`SARINA_ACCESS_TIER` in `sarina.env`) and the file's `access_tier`. Her own setting
  is in a file her account can write; the cap is not. Without an `access_tier` in the file she is read-only (tier 0).
- hands a conversation to a `claude_cli` or `claude` tier only while an approval for that tier (and session, if the request
  named one) is in the file and not expired, whatever the tier's `auto` setting says. Otherwise she files a request, tells the
  operator the command, and goes on without that tier.

While the file does not exist, Sarina behaves as before (her own setting, the operator's `[y/N]` question for tiers whose
`auto` is false). That keeps existing installations working until the owner switches the gate on.

## Why an agent cannot approve its own request

- Writing the decisions needs root: the owner's password. No agent account has it, and no passwordless sudo rule for an
  agent (a future `sarina-sudo` allow list) may ever include `heimdalld`.
- `heimdalld grant` refuses to decide when standard input is not a terminal, when `sudo` was used by the `sarina` account,
  or when any process above it (its parent, their parent, up to the start of the system) is Sarina's program
  (`sarina`, `sarina-service`) or runs as the `sarina` account. A shell command Sarina started is below her, so it is named and
  refused even if it somehow had root.
- The request's reason is the agent's own text: `grant approve` shows it as untrusted, quoted.

This is the single gate the Phase 4 plan asked for (`ARCHITECTURE.md`): in Sarina, every hand-off to another tier passes
through one function (`tiers.Router.attempt`), and every default permission through one (`config.AccessTierFromEnv`); both
consult the same file through `go/heimdall/grants.go`.

## Not covered

- Sarina's `council` tool asks other models (some may be online) for advice. It is not a hand-off of the conversation, and it
  asks the operator before every online call (`[y/N]`, or no online members when nobody can be asked). It does not go through
  this gate.
- `--allow-write` / `--allow-shell` typed by the operator on one command still add to the tier for that run: the operator's own
  decision. An agent without a shell cannot type them.
