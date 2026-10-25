# Immunity: malware Heimdall learns that ClamAV does not know

ClamAV is the reference: the signatures the world already shares. Immunity is what Heimdall adds from what happened on this computer.

1. **Suspect.** A sample is kept in a root-only store (`/var/lib/heimdall-immunity`, compressed, not runnable): a file the owner
   names, or what a containment found (an unapproved behaviour file such as a planted skill, the program a suspicious Sarina process
   ran when it was not an installed package's).
2. **Confirm** (the owner, with sudo). The sample is checked against ClamAV first. If ClamAV knows it, nothing is learned (its
   signature is noted: the reference covers it). If ClamAV does not, its fingerprint (SHA-256 and size) is written to
   `/var/lib/clamav/heimdall-immunity.hsb`, which ClamAV loads with its own database.
3. **Immune.** From then on every scan (the downloads watch, Settings > Security's scan, `heimdalld scan-files`, ClamAV itself)
   reports any copy of it, anywhere, as `Heimdall.Immunity.<kind>.<id>`; the downloads watch quarantines it like any definite
   find. When the fingerprints change, the next scan looks at every file again, so copies that arrived earlier are found too.

Nothing is learned without confirmation: a wrong fingerprint would quarantine a good file. Files that belong to an installed package
are refused (unless `--force`), and so are files under 64 bytes.

```
sudo heimdalld immunity add --reason "why" FILE      keep, check against ClamAV, learn it if ClamAV does not know it
sudo heimdalld immunity suspect --reason "why" FILE  only keep it
sudo heimdalld immunity list                          suspect / immune / reference
sudo heimdalld immunity confirm SHA256                a kept suspect is malware: learn it
sudo heimdalld immunity forget SHA256                 a mistake: remove it and its fingerprint
heimdalld immunity check FILE                         is this something Heimdall learned? (any user)
```

## Limits and the next step

A fingerprint catches exact copies only; one changed byte makes a new file. Catching variants needs rules built from what the sample
does and contains: the analysis step (the sample taken apart in Limbo with Ghidra, a rule drafted from it, the owner approving the
rule), which builds on the samples kept here.
