# Tool rules: Heimdall on a computer full of security tools

Written 2026-11-07 for LykanOS, where Heimdall is installed but off until it "has a rule for each BlackArch tool, so it
neither stops them working nor gets turned against the system through them" (my decision that day).

## The problem

On a penetration-testing system the tools do, on purpose, what Heimdall exists to notice: a scanner opens thousands of new
connections, a brute-forcer hammers one host, a framework holds connections to machines it controls. Without rules, either
Heimdall drowns the person in alerts, or it is switched off. And an attacker on such a system would gladly hide behind a
tool's name: a changed `nmap` doing "what nmap does" is the perfect cover.

## What the rules do

In force only where `/etc/heimdall/security-tools` exists (LykanOS's image ships it; Labyrinth's does not). The catalog is
`internal/toolrules/tool-rules.json`, built into Heimdall: for each tool its packages, the detectors whose findings are its
normal work (`expects`), whether its new destinations are only summarised (`quiet`), and whether it has no business on the
network at all (`offline`).

A finding about a process (the connection watcher names its program file, `exe`, and for an interpreted tool the script,
`script`: sqlmap's `sqlmap.py`, Burp Suite's jar, Metasploit's `msfconsole`) goes through these steps:

1. **Not a catalogued tool** (no package, another package): unchanged.
2. **Verified?** The file's SHA-256 is compared with the one its package recorded (pacman's own `mtree`). A difference keeps
   the finding as it was and adds a **critical, firm** `tool-rules` alert: the tool was changed. Once an hour per file and
   content.
3. **Started by an AI agent** (Sarina among its parent processes): shown, at least as a warning, "[sarina started Nmap]".
   What an agent runs is never quiet.
4. **An offline tool connecting** (hashcat, john, radare2, binwalk, ...): at least a warning.
5. **Its normal work**, for the verified file: written as info, "[Nmap, a verified security tool] ...". A quiet tool's new
   destinations: the first is written, the next ones for 10 minutes only counted, and the count goes into the next line.

Critical findings are never softened: a scanner reaching an address on a threat list is still worth a look. The process's
other arguments are never read (password crackers take passwords there); only the script's path.

## Not covered yet

- Detectors without a process: Wi-Fi checks (aircrack-ng's monitor mode, deauthentication seen nearby), listeners on ports
  outside the ecosystem's own, malware scans of payloads a tool writes (msfvenom's output is malware by design). Each needs
  its own rule, and testing with the tool on a LykanOS system.
- Tools beyond LykanOS's core list (`profile/packages.x86_64`): a package not in the catalog gets no rule, so its findings
  stay as they are. Adding one is a catalog line and a test.
- Command-and-control frameworks (Sliver, Merlin): Heimdall's remote-access catalog calls them implants, critical, never
  approvable. On LykanOS the operator's own server is legitimate; telling it from an implant needs a rule of its own.

## Switching Heimdall on in LykanOS

Not yet (my decision stands until the rules are tested with the tools): `sudo heimdall-enable-defaults --force && sudo
systemctl start heimdall`, after checking in a LykanOS VM that scans, brute-force runs and Metasploit sessions produce the
summarised info lines above and nothing critical.
