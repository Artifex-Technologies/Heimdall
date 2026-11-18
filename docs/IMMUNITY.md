# Immunity: quarantine, the owner's judgement, and malware Heimdall learns

ClamAV is the reference: the signatures the world shares (Cisco Talos, updated several times a day). It lists known *bad* files,
so a good file not being in it is normal. Immunity is what Heimdall adds from what happens on this computer.

## The flow

1. **Held.** A suspicious file is moved into Heimdall's quarantine (`/var/lib/heimdall-immunity`: the sample compressed and
   unrunnable, root's only; the index readable by the heimdall group). ClamAV is asked at once, nobody needs to approve that:
   - ClamAV knows it: it is malware (**reference**). It stays held.
   - ClamAV does not: it is **held**, and the owner is told (a notification; Settings > Security lists it).
   What gets held: containment's evidence (Sarina's behaviour files that are not as the owner signed, once trust is on; a program a
   suspicious Sarina process ran that is not an installed package's), and whatever the owner holds by hand. Never anything under
   `/usr`, `/boot`, `/proc`, `/sys`, `/dev`, `/run`, nor a file an installed package owns.
2. **Report.** Each held file gets a report made by reading it, never running it: its kind, entropy (packed or encrypted?), for a
   program the ELF header (interpreter, libraries, stripped or not), the telling strings (addresses, paths, commands), the first
   2 KiB of a text file. Sarina reads it (it is untrusted text: evidence, never instructions) and writes the owner an analysis.
3. **Analysed in Limbo.** Each held file is queued for an analysis in Limbo's sealed `malware-analysis` machine (no network, no
   sudo, no shared folder; the file is sent in over ssh, stored read-only and never run; the machine is destroyed afterwards; Limbo's
   docs/SAMPLES.md). The image's `limbo-decompile` gives the triage (file type, hashes, imports, sections, strings, YARA matches) and
   the function list. The result is kept with the held file (`analysis`), shown in Settings and to Sarina, whose review uses it; it is
   untrusted text. `sudo heimdalld immunity analyze SHA256` runs one by hand. Without Limbo the analysis is recorded as unavailable
   and nothing else changes.
4. **Judged.**
   - The owner: **Release** (it is good: back exactly as it was, owner, mode and time) or **It's malware** (learned, below).
   - A proof: Heimdall itself releases a held file when it can show it was there before: the owner signed exactly this content
     (trust list), or Heimdall's **inventory** had exactly this file at this path a day or more before it was held. For files that
     decide how an AI agent behaves only the owner's signature counts (a planted skill could lie there for a day). `heimdalld contain
     release` does this for what the containment held; Sarina asks for it when a program that was there before stops working (a
     failed service, a crash) because its file is held. A request only names the file; root checks the proof, so a request (from
     Sarina or anyone) can never release more than the proof covers, and nothing is released while Sarina is contained.
5. **Learned.** Malware ClamAV does not know gets a fingerprint (SHA-256 and size) in `/var/lib/clamav/heimdall-immunity.hsb`,
   which ClamAV loads with its own database: every scan from then on catches any copy, anywhere, as `Heimdall.Immunity.<kind>.<id>`.
   When the fingerprints change, the next scan looks at every file again.

## The inventory

Root (`heimdall-inventory.timer`, daily, idle priority) records each program outside the packages with its SHA-256 and when it was
first seen with that content: `/usr/local`, `/opt`, `~/.local/bin`, `~/bin`, user services and desktop entries. Neither the user,
Sarina nor the daemon's account can write it.

## Commands

```
sudo heimdalld immunity hold --reason "why" FILE      quarantine it (ClamAV asked at once)
sudo heimdalld immunity list                           held / reference / immune / released / suspect
sudo heimdalld immunity release SHA256                 it is good
sudo heimdalld immunity release-if-proven SHA256       only with a proof
sudo heimdalld immunity confirm SHA256                 it is malware: learn it
sudo heimdalld immunity analyze SHA256                 take it apart in Limbo's sealed machine now
sudo heimdalld immunity analyze --sarina SHA256        ask Sarina for a static analysis (below)
sudo heimdalld immunity add --reason "why" FILE        hold and learn in one step
sudo heimdalld immunity take-limbo SHA256              keep a copy of a file Limbo held at a guest's exchange
sudo heimdalld immunity forget SHA256                  a mistake: remove it and its fingerprint
heimdalld immunity check FILE                          is this something Heimdall learned? (any user)
```

## Files Limbo held at a guest's exchange

When a guest puts a file in its outbox, Limbo scans it with ClamAV before handing it out. A file ClamAV knows is not handed
out: Limbo moves it to `/var/lib/limbo/state/exchange-held/<sha256>` (root-only) and writes `exchange.held` with the guest,
the guest's path for it, the SHA-256, the size and the signature. Heimdall raises a `limbo-exchange` warning for it, and the
alert's explanation names the command that takes a copy into this store:

```
sudo heimdalld immunity take-limbo SHA256
```

What it does, and what it never does:

- It is asked for by SHA-256 only. The path is Limbo's folder plus that name; the guest's own path from the event is never
  used for anything but display.
- The file is opened without following links, and its content must hash to its name before anything is stored. So only
  exactly what Limbo held can come in.
- Nothing is run. The bytes are hashed, compressed into the store (root's only), read for the report, and given to ClamAV.
- Limbo's copy stays where it is: it is Limbo's evidence.
- ClamAV knowing it makes a **reference** entry (nothing new to learn). If this computer's ClamAV does not know it, it stays a
  **suspect** for the owner to `confirm`.

### Taking the copy automatically (built 2026-11-07, approved 2026-11-05)

On each `exchange.held` alert, heimdalld (the unprivileged daemon) leaves `{"take_limbo": "<sha256>"}` in
`/var/lib/heimdall-requests` (the root request queue, mode 1733), and `heimdall-requests.service` (root) takes the copy, four
per run at most. For that the daemon's unit can also write the queue (`ReadWritePaths=-/var/lib/heimdall-requests` in
`heimdall.service`). The request is safe whoever writes it: it can only make root copy a file Limbo already holds, checked
against its hash, from one root-only folder into another. Disk use is bounded by what Limbo holds and by the 256 MiB sample limit.

The guest that tried to hand the file out is also restricted (`limbo-exchange` on `exchange.held` triggers the same Limbo
quarantine as a network probe; approved 2026-11-05).

## Sarina's analysis (built 2026-11-17)

I approved this on 2026-11-17 (Ghidra BSim comes later). Heimdall may ask Sarina to read a held file with her
`reverse_engineer` tool: REA with Ghidra inside the `labyrinth-rea` sandbox (no network, files read-only, static commands only;
Labyrinth_OS `docs/REA.md`). Drivers and new malware have no write-ups; reading what they do is how a rule gets written.

**When.** The standing permission is `sarina_analysis` in `/etc/heimdall/config.json` (readable by all, so Settings shows it):

- `"ask"` (the default): only when I ask, `sudo heimdalld immunity analyze --sarina SHA256`. A new held file is not sent; the
  notification names that command.
- `"auto"`: also every new held file ClamAV does not know (a hold, or a copy taken from Limbo's exchange): the hold leaves
  `{"sarina": "<sha256>"}` in the root request queue and `heimdall-requests.service` runs it after the other requests, one per
  run. Root checks again whatever the request says: the switch, that the file is held, unknown to ClamAV and not yet looked at.
- `"off"`, or anything else: never, not even when I ask.

Never while Sarina is contained (`/etc/heimdall/contained`). Asking without waiting in a critical case is not built: no hold
carries a severity today, and the most critical one (containment's evidence) is exactly when Sarina must not be asked; `"auto"`
is how to let Heimdall ask at once.

**How, and the safety checks.**

1. One at a time (a lock in the store); a second request is refused.
2. Root lends the sample: an uncompressed copy at `/var/lib/heimdall-sarina-share/<sha256>.sample`, root:sarina 0440 in a
   root:sarina 0750 folder that is made there and never followed if something else stands in its place. Sarina's service
   account sees it as `/quarantine/<sha256>.sample` (its labyrinth quarantine folder is a link to the share). The copy is
   removed when the answer is in, on every path; the sample in the store is never touched.
3. Heimdall opens a session on Sarina's service (`sarina_url`, loopback only) with `tool_allowlist: ["reverse_engineer"]`,
   no shell, no writing, at most 12 turns and 10 tool calls, and sends nothing unless the service reports exactly one tool
   (`sarina_contract_tools_mismatch` otherwise: an older service ignores the allowlist and would report every tool; a service
   without the tool switched on reports none). The session is closed on every path; the whole analysis may take 20 minutes.
4. The request names the file by its sandbox path and frames the file's facts (hash, size, kind, where it was held from and
   why) as untrusted data: a name or a reason can come from an attacker, and so can every string inside the file.
5. Her answer is untrusted text. It is kept with the held file (`sarina_analysis` in the index: time, trigger, status, output
   up to 32 KiB, error, rule draft) and shown labelled as hers. It can never release, delete or run anything; a failure is kept
   too, so I see why there is none. A YARA rule in it (a ```yara block) becomes a rule draft only if it passes the draft checks
   below, and then waits for `rule test` and my approval like any other.

Her session is written to her session folder like any other, so Heimdall's own watch reads it too (strings from a sample can
look like an injection there: that is evidence, not her doing).

**Setting it up on Sarina's side** (once): `SARINA_REVERSE=on` in `/etc/sarina/service.env`,
REA and Ghidra where the `sarina` account can read them (`LABYRINTH_APPS`), and its quarantine folder linked to the share:
`/var/lib/sarina/.local/share/labyrinth/quarantine -> /var/lib/heimdall-sarina-share`. It needs a Sarina that reads
`/quarantine/...` paths (Sarina, 2026-11-17). With `SARINA_REVERSE=on`, other service sessions that do not narrow their tools
are offered the reverse tools too.

## Rules: catching variants (YARA)

A fingerprint catches exact copies only. A rule catches what a sample *contains* (strings, byte patterns), so it also
catches the variants a fingerprint misses. ClamAV loads YARA rules from its database folder next to its own signatures and
reports a match as `YARA.<rule name>`.

1. **Drafted.** Sarina reads the held sample's report and Limbo's analysis (triage strings, imports, functions) and drafts a
   rule with her `draft_yara_rule` tool: `POST /v1/rules/drafts` with `{"sample_sha256": "...", "rule": "...", "note": "..."}`. The owner can draft one too:
   `sudo heimdalld immunity rule draft SHA256 FILE`. Heimdall keeps a draft only if it is one rule, named `Heimdall_...`, with
   a condition, without `import` or `include` (an include would make ClamAV read another file), at most 16 KiB, for a sample
   Heimdall holds. A `rule-draft` alert names the next command. Drafts live in `/var/lib/heimdall/rule-drafts.json`.
2. **Tested** (root): `sudo heimdalld immunity rule test ID`. The rule and the sample are put in a fresh root-only folder
   and ClamAV runs with only that rule loaded (seconds, not the full database). It must match the sample, and it must match
   none of this computer's own programs (`/usr/bin`, `/usr/local/bin`, `/usr/lib/systemd`; `--fp DIR` to choose). The sample is
   read, never run. The result is kept with the exact text tested.
3. **Approved** (the owner): `sudo heimdalld immunity rule approve ID` shows the rule and asks for `yes`. Only a draft whose
   current text passed its test can be approved, and never from a command an AI agent started (the same guard as the grant
   gate, `GRANTS.md`). It is installed as `/var/lib/clamav/heimdall-rule-<name>.yar`; every ClamAV scan uses it from then on,
   and `heimdalld scan-files` scans everything again once.
4. **Rejected or removed**: `sudo heimdalld immunity rule reject ID` (an approved rule is removed from ClamAV).

`heimdalld immunity rule list` and `rule show ID` show the drafts, who drafted them (the account, read from the kernel), and
their tests.

Tested on this PC: a rule drafted for a held demo script matched it and none of the 3203 programs in `/usr/bin` (about 40
seconds), and after approval ClamAV reported the script as `YARA.Heimdall_demo_dropper.UNOFFICIAL`. A rule without strings
(`condition: true`, "everything") is not loaded by ClamAV, so it matches nothing and fails its test.

## Limits

- A rule is only as good as its strings: one taken from a common library would match harmless programs. The test catches
  the programs it scans, not every file on every computer; read the rule before approving it.
- Sarina sends a draft with her `draft_yara_rule` tool (Sarina `d225526`, beside `reverse_engineer`; approved 2026-11-05).
  She can only draft: testing and approving stay with the owner, as root. `rule draft` still works by hand.
