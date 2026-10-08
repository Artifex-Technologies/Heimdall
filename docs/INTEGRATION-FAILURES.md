# Sarina integration failures: runbook

For an operator or the Sarina agent. Heimdall touches Sarina in three ways; each
can fail without ever stopping Heimdall's detection loop.

| Path | Direction | Code prefix |
| --- | --- | --- |
| Advisory consultation after a Limbo quarantine (`internal/response`) | Heimdall -> `sarina-service` (`sarina_url`, loopback) | `sarina_*` |
| Reading Sarina's session files (`internal/sources/agentsource`) | Heimdall reads `<agent_session_dir>/agent/*.json` | `agent_session_*` |
| Memory-write review (`internal/governance`, `POST /v1/review`) | Sarina -> Heimdall (`api_addr`, default `127.0.0.1:8930`) | none; Sarina fails open |

Every failure is written to Heimdall's own alert stream (stdout, `alert_log_path`,
`GET /v1/alerts`) as an alert with `detector_id: "integration"`, `severity:
"warning"`, and `fields.error_code` / `fields.remedy`. The `summary` reads
`<code>: <what happened> (remedy: <next step>)`. Find them with:

```bash
curl -s 'http://127.0.0.1:8930/v1/alerts?n=500' | grep -o '"error_code":"[a-z_]*"'
grep '"detector_id":"integration"' /var/log/heimdall/alerts.jsonl   # path = alert_log_path
```

An advisory failure never costs the quarantine: the guest is already
restricted and the human still gets the evidence; only Sarina's opinion is
missing.

## Limbo quarantine (control socket)

The alert that triggers a quarantine is always stored first. The request is then
queued and run in the background: `Write` never waits for Limbo, so a hung Limbo
socket cannot stall the detection loop. Rules:

- **Queue, not drop.** Each call has a 10 s budget. At most 8 Limbo calls run at once; further requests wait
  in a pending queue and are all eventually sent. Triggers are coalesced per
  guest (one pending request per guest; a repeat while queued is merged, a repeat
  while its call is in flight is logged), so the queue is bounded by the number
  of guests. A hard cap of 1024 distinct waiting guests exists as a sanity
  limit; beyond it the request is recorded as `limbo_quarantine_overflow`.
- **Order** is deterministic and involves no model: highest alert severity first,
  then oldest first. A repeat trigger for a queued guest merges its event kinds
  into the request (Limbo's reason/evidence list them) and raises its priority if
  the new alert is more severe; it never lowers it.
- **Re-check before sending.** Immediately before the call Heimdall skips the
  request and records `quarantine_skipped` (with the reason and `queue_wait`) if:
  a later Limbo event for the guest shows `guest.stop` (guest gone) or
  `policy.apply` (condition cleared) after the trigger; or Limbo's read-only
  `GET /v1/quarantine` on the control socket shows a holding record (status
  `open` or `dangerous`) at level `isolate`, or at `restrict` opened *after* the
  trigger (a restrict hold older than the trigger may predate the change that
  triggered it, so the request is still sent to re-assert it). If the status
  cannot be determined (error, timeout, no `GET` support) the request is sent:
  the re-check fails toward acting.
- **Visibility.** Queue wait is sent to Limbo as evidence (`queue_wait`) and put
  on failure/skip alerts. A request waiting longer than 15 s
  (`limbo_quarantine_delay_seconds`) raises `limbo_quarantine_delayed` once.
  While more than 4 requests wait (`limbo_backlog_threshold`) a
  `limbo_quarantine_backlog` alert is raised at most once a minute; if Sarina is
  configured, ONE advisory (counts, guests, severities only) is requested for it
  and recorded as a separate `quarantine_backlog_advisory` alert marked
  `untrusted`. It is a note for a human: it never reorders, skips or acts.
- **Shutdown.** Heimdall stops accepting triggers, waits 3 s for the queue and
  in-flight calls, then cancels. Requests still queued are recorded as one
  `quarantine_not_completed_at_shutdown` alert naming the guests
  (`fields.guests`). Abandoned in-flight calls are still only logged. A trigger
  that arrives during shutdown is recorded the same way.

A successful quarantine is only logged, as before.

| Failure mode | Code | Symptom | How Heimdall detects it | Remedy |
| --- | --- | --- | --- | --- |
| Socket accepts but Limbo does not answer within 10 s | `limbo_quarantine_timeout` | guest alert stored, hold may not be in force | context deadline / client timeout | check `limbod` is not hung (`systemctl status limbo`); restrict the guest by hand meanwhile |
| Socket missing, refused, or wrong path | `limbo_unreachable` | guest alert stored, no quarantine | dial error | start Limbo; check `limbo_control_socket` |
| Limbo answered with an error or a malformed reply | `limbo_quarantine_failed` | guest alert stored, no quarantine | HTTP error or decode error; the message quotes Limbo's reason | `journalctl -u limbo`; restrict the guest by hand |
| A queued request has waited past `limbo_quarantine_delay_seconds` (default 15 s) | `limbo_quarantine_delayed` | guest alert stored, hold not yet requested (once per request; fields `guest`, `queue_wait`, `backlog`) | monitor tick over the pending queue | check `limbo_quarantine_timeout` / `limbo_unreachable` alerts and `systemctl status limbo`; restrict critical guests by hand |
| More than `limbo_backlog_threshold` (default 4) requests waiting | `limbo_quarantine_backlog` | many guests unrestricted while Limbo is slow (at most once a minute; fields `backlog`, `guests`, `in_flight`) | monitor tick | as above; optional Sarina note arrives as `quarantine_backlog_advisory` (untrusted, `fields.advisory`) |
| More than 1024 distinct guests waiting | `limbo_quarantine_overflow` | that guest was **not** queued | hard sanity cap | something is generating triggers for a huge number of guests; check Limbo; restrict the guest by hand |
| Re-check found the request unnecessary | `quarantine_skipped` | no Limbo call; `fields.reason` says why (guest stopped, policy re-applied, already held at `isolate`, or at `restrict` after the trigger) | Limbo events seen after the trigger, plus a read-only `GET /v1/quarantine` | none needed if the guest is as restricted as intended |
| Heimdall shut down with requests still queued (or a trigger arrived during shutdown) | `quarantine_not_completed_at_shutdown` | guests never sent to Limbo (`fields.guests`) | pending queue non-empty after the 3 s grace | restrict those guests by hand with the Limbo CLI; Heimdall does not retry after restart |

Each is an integration alert (`detector_id: "integration"`, `fields.guest`,
`fields.error_code`, `fields.remedy`). A recorded-but-not-enforced hold
(`Applied: false`) is still only logged ("NOT enforced"). The human-visible
quarantine record is unchanged: source `sentry:limbo-guest`, reason = the alert
summary, evidence = detector, event kind, alert time.

## Advisory consultation (Sarina service)

Behaviour that applies to all rows: session creation sends `tool_allowlist: []`;
evidence is sent only if the reply says `tools == 0`; the session is `DELETE`d
on every path (including errors and an already-expired context); a refused or
dropped connection is retried once after 2 s, nothing else is retried; at most
2 advisories run at once (a third is skipped as `sarina_busy`); one advisory has
a 3 minute budget and the HTTP client a 150 s timeout.

| Failure mode | Code | Symptom | How Heimdall detects it | Remedy |
| --- | --- | --- | --- | --- |
| Sarina down / restarting / wrong port | `sarina_unreachable` | quarantine exists, no advisory | connection error on both attempts | start `sarina-service`; check `sarina_url` |
| Slow model, chat exceeds budget | `sarina_timeout` | no advisory after ~2.5 min | client timeout or context deadline (not retried) | check the model server; Sarina keeps working on it, Heimdall has already `DELETE`d the session |
| Bad or missing token | `sarina_auth` | no advisory | HTTP 401 or 403 | set `sarina_token` or `SENTRY_SARINA_TOKEN` to Sarina's `SARINA_SERVICE_TOKEN` |
| Service ignores `tool_allowlist` (old build) or reports tools != 0 or omits `tools` | `sarina_contract_tools_nonzero` | no advisory; **no evidence was sent** | `tools` missing or not 0 in the create reply | upgrade `sarina-service`; verify with the create command below |
| Session evicted mid-conversation | `sarina_session_evicted` | no advisory | HTTP 404 on chat | transient (Sarina restart or `--max-sessions`); the next advisory opens a new session. Persistent: raise `--max-sessions` |
| Sarina internal error | `sarina_server_error` | no advisory | HTTP 5xx; the service's `detail` is quoted in the message | `journalctl -u sarina-service`; the message holds the reason |
| Malformed, truncated, empty or oversize reply; request rejected (4xx, e.g. `sarina_cwd` missing); unusable `session_id` | `sarina_bad_response` | no advisory | JSON decode error, empty `final_output`, body over 1 MiB, HTTP 4xx other than 401/403/404, `session_id` not `[A-Za-z0-9_-]{1,64}` | the message says which; check `sarina_cwd` exists, and that `sarina_url` is `sarina-service` and not another server |
| Model backend failed (HTTP 200 with `stop_reason: backend_error`) | `sarina_backend_error` | no advisory | `stop_reason` field | check `OPENAI_BASE_URL` and the model server |
| Too many advisories in flight | `sarina_busy` | advisory skipped | concurrency slot unavailable | wait; quarantine unaffected |
| Anything else in advisory code (including a panic) | `sarina_error` | no advisory | recovered panic | report as a Heimdall bug |

Replies longer than 16 KiB are truncated (valid UTF-8 boundary) and stored as an
advisory, labelled untrusted by Limbo's side.

### Commands to check

```bash
curl -s http://127.0.0.1:8899/healthz                       # {"status":"ok","active_sessions":N}
# Contract check. Expect {"session_id":"...","tools":0}. Anything else is sarina_contract_tools_nonzero.
curl -s -X POST http://127.0.0.1:8899/v1/sessions \
  -H "Authorization: Bearer $SENTRY_SARINA_TOKEN" -H 'Content-Type: application/json' \
  -d '{"cwd":"/var/lib/heimdall","tool_allowlist":[]}'
# 401 or 403 = sarina_auth. Clean up the test session:
curl -s -X DELETE http://127.0.0.1:8899/v1/sessions/<session_id> -H "Authorization: Bearer $SENTRY_SARINA_TOKEN"
journalctl -u sarina-service -n 50 --no-pager
journalctl -u heimdall -n 50 --no-pager | grep -i sarina
```

An empty `SARINA_SERVICE_TOKEN` means Sarina has auth off; a token set only on
Heimdall's side is harmless.

## Reading Sarina's session files

Heimdall polls every `poll_interval`; a problem never stops the poll, files that
can be read are still scanned, and each distinct problem is reported once per
file version (a persistent directory error once until it clears).

| Failure mode | Code | Symptom | How Heimdall detects it | Remedy |
| --- | --- | --- | --- | --- |
| `agent_session_dir` missing, wrong, or not traversable | `agent_session_unreadable` | no agent alerts at all (looks like "clean") | `stat` of the directory fails | `ls -ld <dir>`; fix the config path or give heimdalld's user `x` on the path |
| A session file cannot be opened (permissions, it is a directory) | `agent_session_unreadable` | that session is not scanned | `ReadFile` error | `ls -l <file>`; grant heimdalld's group read |
| File is invalid JSON and has been unmodified for more than 5 s (damaged, or not Sarina's format) | `agent_session_malformed` | that session is not scanned | JSON decode error on a settled file | inspect the file; Sarina rewrites it on its next turn |
| Message in a shape Heimdall cannot decode (a number, content as an array of parts, ...) | `agent_session_unknown_shape` | those messages are not scanned; the rest are | message is neither string nor `{role,content,tool_calls}` | Sarina's format changed: compare `docs/spec/01-agent-core.md` section 4.2 with `agentsource` and report to Sarina's board |
| Session file being written while read | none | none | invalid JSON on a file modified within 5 s: silently retried next poll | none needed |

`heimdalld scan` treats any of these as an incomplete audit: it prints
`heimdalld: warning: <code>: ...` and exits 2 even with no findings.

```bash
ls -ld /path/to/.port_sessions /path/to/.port_sessions/agent
ls -l /path/to/.port_sessions/agent | head
sudo -u heimdall head -c 300 /path/to/.port_sessions/agent/<id>.json   # can heimdalld's user read it?
python -c "import json,sys; json.load(open(sys.argv[1]))" /path/to/.port_sessions/agent/<id>.json
heimdalld scan --config /etc/heimdall/config.json                          # exit 2 + warnings = incomplete
```

## Sarina consulting Heimdall (`POST /v1/review`)

Heimdall only answers; failures here show on Sarina's side (she fails open on
absence and closed on `"deny"`). Check that Heimdall is up and the URL matches
Sarina's `SENTRY_REVIEW_URL`:

```bash
curl -s http://127.0.0.1:8930/healthz
curl -s -X POST http://127.0.0.1:8930/v1/review -H 'Content-Type: application/json' \
  -d '{"text":"remember the build command","kind":"memory"}'
```
