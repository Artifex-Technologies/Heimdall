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
sudo heimdalld immunity add --reason "why" FILE        hold and learn in one step
sudo heimdalld immunity forget SHA256                  a mistake: remove it and its fingerprint
heimdalld immunity check FILE                          is this something Heimdall learned? (any user)
```

## Rules: catching variants (YARA)

A fingerprint catches exact copies only. A rule catches what a sample *contains* (strings, byte patterns), so it also
catches the variants a fingerprint misses. ClamAV loads YARA rules from its database folder next to its own signatures and
reports a match as `YARA.<rule name>`.

1. **Drafted.** Sarina reads the held sample's report and Limbo's analysis (triage strings, imports, functions) and drafts a
   rule: `POST /v1/rules/drafts` with `{"sample_sha256": "...", "rule": "...", "note": "..."}`. The owner can draft one too:
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
- Sarina has no tool yet that sends a draft (her side is noted on her board); until then she writes the rule in her analysis
  and the owner drafts it with `rule draft`.
