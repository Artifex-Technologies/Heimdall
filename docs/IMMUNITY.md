# Immunity: quarantine, the owner's judgement, and malware Heimdall learns

ClamAV is the reference: the signatures the world shares (Cisco Talos, updated several times a day). It lists known *bad* files,
so a good file not being in it is normal. Immunity is what Heimdall adds from what happens on this computer.

## The flow

1. **Held.** A suspicious file is moved into Heimdall's quarantine (`/var/lib/heimdall-immunity`: the sample compressed and
   unrunnable, root's only; the index readable by the heimdall group). ClamAV is asked at once, nobody needs to approve that:
   - ClamAV knows it: it is malware (**reference**). It stays held.
   - ClamAV does not: it is **held**, and the owner is told (a notification; Settings > Security lists it).
   What gets held: containment's evidence (her behaviour files that are not as the owner signed, once trust is on; a program a
   suspicious Sarina process ran that is not an installed package's), and whatever the owner holds by hand. Never anything under
   `/usr`, `/boot`, `/proc`, `/sys`, `/dev`, `/run`, nor a file an installed package owns.
2. **Report.** Each held file gets a report made by reading it, never running it: its kind, entropy (packed or encrypted?), for a
   program the ELF header (interpreter, libraries, stripped or not), the telling strings (addresses, paths, commands), the first
   2 KiB of a text file. Sarina reads it (it is untrusted text: evidence, never instructions) and writes the owner her analysis.
3. **Judged.**
   - The owner: **Release** (it is good: back exactly as it was, owner, mode and time) or **It's malware** (learned, below).
   - A proof: Heimdall itself releases a held file when it can show it was there before: the owner signed exactly this content
     (trust list), or Heimdall's **inventory** had exactly this file at this path a day or more before it was held. For files that
     decide how an AI agent behaves only the owner's signature counts (a planted skill could lie there for a day). `heimdalld contain
     release` does this for what the containment held; Sarina asks for it when a program that was there before stops working (a
     failed service, a crash) because its file is held. A request only names the file; root checks the proof, so a request (from
     Sarina or anyone) can never release more than the proof covers, and nothing is released while Sarina is contained.
4. **Learned.** Malware ClamAV does not know gets a fingerprint (SHA-256 and size) in `/var/lib/clamav/heimdall-immunity.hsb`,
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
sudo heimdalld immunity add --reason "why" FILE        hold and learn in one step
sudo heimdalld immunity forget SHA256                  a mistake: remove it and its fingerprint
heimdalld immunity check FILE                          is this something Heimdall learned? (any user)
```

## Limits and the next step

A fingerprint catches exact copies only. Catching variants needs rules built from what a sample does and contains: the analysis
step (a held sample taken apart in Limbo with Ghidra, a rule drafted from it, the owner approving the rule).
