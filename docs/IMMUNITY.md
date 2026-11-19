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
3. **Analysed in Limbo.** Each held file is queued for an analysis in Limbo's sealed `malware-analysis` machine (no route out: network mode `none`, or `sinkhole`, where what it tries to reach is only logged; no
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

I approved this on 2026-11-17 (Ghidra BSim followed on 2026-11-18: "Similar programs" below). Heimdall may ask Sarina to read a held file with her
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
   up to 32 KiB, error, rule draft, whether it was compared with the library) and shown labelled as hers. It can never release, delete or run anything; a failure is kept
   too, so I see why there is none. A YARA rule in it (a ```yara block) becomes a rule draft only if it passes the draft checks
   below, and then waits for `rule test` and my approval like any other.

**Similar programs (built 2026-11-18).** When Sarina's service account has a similarity library
(`/var/lib/sarina/.local/share/labyrinth/rea-work/bsim/library.mv.db`: a Ghidra BSim database of every program it analysed
before, made once at setup; Labyrinth_OS `docs/REA.md`), the request asks one thing more: run `reverse_engineer` with the
command `similar` and copy the closest programs and functions it lists, with their scores. That command compares the held
file's functions with the library inside the same sandbox (nothing is run) and then adds the file, so the next held file
can be matched against it ("shares three functions with `<sha256>.sample` at 1.000"). Held files are named by their SHA-256
there, so a match points at a held file `heimdalld immunity list` shows, with its ClamAV name or its own analysis. The kept
analysis records `similar: true`; what she found is in her answer with the rest, untrusted like it: a match is a hint
that code is shared (a common library matches too), not proof of the same family. Only a plain file counts as the
library; without one the request is as before.

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
   Heimdall holds, and only if it passes the lint and YARA-X's check below. A `rule-draft` alert names the next command.
   Drafts live in `/var/lib/heimdall/rule-drafts.json`, with the lint's warnings (`warnings`).
2. **Tested** (root): `sudo heimdalld immunity rule test ID`. The rule and the sample are put in a fresh root-only folder
   and ClamAV runs with only that rule loaded (seconds, not the full database). It must match the sample, and it must match
   none of this computer's own programs (`/usr/bin`, `/usr/local/bin`, `/usr/lib/systemd`; `--fp DIR` to choose). The sample is
   read, never run. The result is kept with the exact text tested. The test runs the lint and YARA-X's check again first (the
   checker may have been installed since the draft): a rule YARA-X does not compile fails without a scan, and the warnings
   are refreshed and shown.
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

### Checking a draft: the lint and YARA-X (built 2026-11-18)

Item R4 of my reference plan (in my private plans: Labyrinth_OS docs/plans/PLAN_REFERENCE_2026-11.md); I decided on 2026-11-18 to use YARA-X for the exact check.

**The lint** (Go `internal/immunity/rulelint.go`, Rust `rust/heimdall/src/rulelint.rs`, the same answers:
`testdata/parity/rulelint.json`). ClamAV is still where an approved rule goes, and it loads only part of YARA, so what it
would not load is refused when the draft is sent, not discovered at the test. I tried each limit with ClamAV 1.5 and a
one-rule database (`clamscan -d`); its manual says the same where it says anything:

| Refused | Why |
| --- | --- |
| `global` or `private` rule | global rules are not supported; a private rule loads but never reports a match |
| no strings, more than 64 strings | ClamAV needs at least one string and allows 64 |
| a text string under 2 bytes; a hex string without 2 fixed bytes in a row (in each part between jumps) | "string is too short", "Can't find a static subpattern of length 2" |
| `xor`, `base64`, `base64wide` or `private` on a string | a parse error: the rule is not loaded |
| `~` (not) or a comment inside a hex string | a parse error |
| a regular expression with flags (`/i`, `/s`) | loaded, but the flag is ignored: it would never match what it means to |
| a string the condition does not use | "unreferenced string" |
| `contains`, `matches`, `startswith`, `endswith`, `iequals` and their `i` forms, or a match length (`!a`) in the condition | not supported (one crashed clamscan) or a parse error |

Warnings never refuse a draft; they are kept with it and shown by `rule draft`, `rule show` and `rule test`, and the API's
answer to `POST /v1/rules/drafts` carries them as `"warnings"` (omitted when there are none):

- a string without 4 fixed bytes in a row (what YARA-X calls a slow pattern: its atoms are poor, and it matches by chance);
- a string that is one byte repeated (`00 00 00 00`, spaces), or one of the strings in nearly every program or page (`MZ`,
  `This program cannot be run in DOS mode`, `kernel32.dll`, `http://`, `/bin/sh` and a few dozen more);
- strings with many wildcards or jumps (16 or more bytes skipped, or an open jump or `*`/`+`) when the condition has no
  `filesize` bound;
- `meta` without `sample_sha256`, `author` or `date`, and an `attack` value that is not a list of ATT&CK technique IDs
  (`T1059`, `T1059.004`, comma-separated).

**YARA-X's check.** `heimdall-yara-check` (`rust/yara-check`, its own package `heimdall-yara-check-git`) is a small program
on the `yara-x` crate (BSD-3, pinned exactly; its notice ships in `/usr/share/licenses/heimdall-yara-check/`). It reads one
rule on stdin, compiles it (no modules, no includes; the rule is never built into a scanner, so no code is generated) and
prints one line of JSON:

```json
{"errors":["E009: unknown identifier `x` (line 6)"],"ok":false,"warnings":["slow_pattern: slow pattern (line 3)"],"yara_x":"1.23.0"}
```

Both daemons run `/usr/bin/heimdall-yara-check` when it is there (a regular executable file), with a clean environment and
at most 30 seconds, as a draft is kept and as it is tested: its errors refuse the draft (`YARA-X does not compile it: ...`),
its warnings are kept marked `YARA-X:` (at most 20, 300 bytes each). Without it, drafts are judged as before by the lint
and ClamAV. When it is there but gives no verdict (it failed, timed out, or printed something else), the draft is judged
without it and the warning says so; it is never refused for that. Tests point `HEIMDALL_YARA_CHECK` at a stand-in.

Why its own package: `yara-x` brings wasmtime and Cranelift. On my desktop (4 build jobs, `nice 19`) a clean release build
takes about 2 minutes 10 seconds and 900 MB of build files for a 3.8 MB program, and it needs Rust 1.95; on a Raspberry Pi
that is much longer, and the daemon itself stays as light as it was. A check takes about 2 ms.

**Limbo's analysis image stays on C YARA for now.** YARA-X's command line (`yr`) is not in Arch's official repositories
(checked 2026-11-18: `pacman -Si yara-x` finds nothing; `extra/yara` 4.5.8 is the C one), only in the AUR (`yara-x`,
`yara-x-bin`). The image's recipe (Sarina `packaging/limbo/decompile`) installs from the official repositories, so it keeps
`yara` until `yr` is packaged there.

## Files I add, and ClamAV's limits

Immunity is about what Heimdall holds. Files I add myself (a font in Settings, an archive Minos unpacks, a copy from a USB drive)
are checked before I use them by `heimdall-fileguard scan` and unpacked by `heimdall-fileguard extract`, the same ClamAV
included, in the privacy package every install has: [PRIVACY_PACK.md](PRIVACY_PACK.md), "Safe file intake". There, too, are
ClamAV's limits (256 MiB per file, 512 MiB per scan, 12 levels, 10,000 files, 2 minutes, AlertExceedsMax): clamscan gets them on
its command line, clamd from the clamd.conf Labyrinth OS ships. A "Heuristics.Limits.Exceeded.*" answer means ClamAV stopped
at a limit, not that it knows the file. `heimdalld immunity` (Go and Rust) does not tell that name apart yet: where clamd runs
with AlertExceedsMax, a held file over the limits would be listed as known to ClamAV under that name. It is still held either
way.

## Limits

- A rule is only as good as its strings: one taken from a common library would match harmless programs. The test catches
  the programs it scans, not every file on every computer; read the rule before approving it.
- Sarina sends a draft with her `draft_yara_rule` tool (Sarina `d225526`, beside `reverse_engineer`; approved 2026-11-05).
  She can only draft: testing and approving stay with the owner, as root. `rule draft` still works by hand.
