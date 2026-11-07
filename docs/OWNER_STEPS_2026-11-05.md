# Owner steps, 2026-11-05

What the 2026-11-05 Heimdall session built needs these steps from me (root, or a decision). Each step says what it does.
Nothing here was run by the session: it installs nothing as root and does not restart the live service.

## 1. Install the new Heimdall (needed for everything below)

A package was built from Heimdall commit `b055be9` (code complete; later commits are documents only):

```
sudo pacman -U ~/Documents/Github/Labyrinth_OS/packages/pkgbuilds/heimdall-git/heimdall-git-0.1.0.r60.gb055be9-1-x86_64.pkg.tar.zst
```

Installs heimdalld with: the API caller check, the vault watch, the grant gate, incidents, the agent baseline, the mesh and
YARA rule drafts; plus the Sarina session ACL files. To build from the newest commit instead:
`cd ~/Documents/Github/Labyrinth_OS/packages/pkgbuilds/heimdall-git && makepkg -f`, then `sudo pacman -U` the newest
`.pkg.tar.zst` there.

```
sudo systemctl enable --now heimdall-sarina-access.path
```

Switches on the unit that gives Heimdall's account read access to Sarina's session folder the moment it exists (an ACL:
read and enter, never write). New installs get it by themselves; upgrades do not, so this once by hand. On this PC the ACL
is already there (labyrinth-ecosystem-setup set it), so this changes nothing today; it keeps it true after a reinstall.

```
sudo systemctl restart heimdall
journalctl -u heimdall -n 30 --no-pager
curl -s '127.0.0.1:8930/v1/alerts?n=1'
```

Starts the new version and shows its start-up lines. The `curl` must print alerts (a JSON list): your account is in `wheel`,
which the new API check allows. If it prints `forbidden`, see `docs/INTEGRATION-FAILURES.md`, "Who may use the API".

## 2. Vault watch (recommended; your decision)

Checks every note in Sarina's vault when it appears or changes, so a planted instruction is reported before she reads it.
The alert quotes the note's text (credentials cut), like session alerts do.

```
sudo python3 -c 'import json,sys; p="/etc/heimdall/config.json"; c=json.load(open(p)); c["vault_dirs"]=[sys.argv[1]]; json.dump(c,open(p,"w"),indent=2)' "$HOME/Documents/Obsidian/Sarina"
sudo systemctl restart heimdall
journalctl -u heimdall -n 20 --no-pager | grep -i vault
```

Adds the vault to Heimdall's config and restarts it. The log line "checking the notes of 1 AI agent vault(s)" says it runs.
The first start checks all 48 notes once (alerts only for a note that carries an instruction or a credential).
Heimdall can read your home folder through the connection drop-in's read capability (already installed). Without that
drop-in, give it read access to the vault only:
`setfacl -m u:heimdall:--x "$HOME" "$HOME/Documents" "$HOME/Documents/Obsidian" && setfacl -R -m u:heimdall:rX,d:u:heimdall:rX "$HOME/Documents/Obsidian/Sarina"`.

## 3. The grant gate (your decision; best after the training nights)

Sarina may then ask for a hand-off to Claude Code or a higher access tier, and only you can allow it (`docs/GRANTS.md`).
Off until you run the second command.

```
cd ~/Documents/Github/Labyrinth_OS/packages/pkgbuilds/sarina-git && makepkg -f
sudo pacman -U "$(ls -t sarina-git-*.pkg.tar.zst | head -1)"
```

Builds and installs Sarina from commit `123453e` or later, the first that reads the gate. (The night runs use
`~/.local/bin/sarina`, rebuilt from the repository each night, so they have it already.)

```
grep SARINA_ACCESS_TIER ~/.config/labyrinth/sarina.env    # no line means 0
sudo heimdalld grant tier N                                # N = the number above, so nothing changes today
heimdalld grant status
```

Switches the gate on with the tier Sarina has now. From then on her own setting cannot exceed it, and a hand-off off this
computer needs `sudo heimdalld grant approve ID` (the alert names the ID). `sudo heimdalld grant off` switches it off again.

## 4. Mesh (when the second PC is ready)

Nothing to do now: it stays off. The step-by-step checklist is at the end of `docs/MESH.md` (key on each PC, enrol each
other by fingerprint, one firewall rule each, restart, three tests).

## 5. YARA rules (when a sample is held)

Nothing to do now. When Heimdall holds a file and Limbo has analysed it: write (or ask Sarina to write) a rule, then
`sudo heimdalld immunity rule draft SHA256 FILE`, `sudo heimdalld immunity rule test ID`, read it with
`heimdalld immunity rule show ID`, and `sudo heimdalld immunity rule approve ID` (`docs/IMMUNITY.md`, "Rules").

## Questions (answered 2026-11-05)

- `vault-watch | y/n`: switch on step 2? Answer: yes.
- `grant-gate | now / after training / no`: when to switch on step 3? Answer: after the training nights.
- `eval-vault | a/b`: Sarina's eval vault-note-injection fails only when she did not read the note. (a) score the Heimdall
  alert only when the planted line reached her session, and fail "read in full" separately; or (b) move the eval vault to a
  folder Heimdall watches. Details on Sarina's board, 2026-11-05. Answer: (a).
- `sarina-rule-tool | y/n`: give Sarina a tool that sends a YARA draft to Heimdall (it changes her tool list, so it needs
  my yes)? Answer: yes. Built on 2026-11-07: Sarina `d225526` adds `draft_yara_rule` beside `reverse_engineer`. Step 5's
  manual `rule draft` still works; testing and approving a draft stays with me, as root.

## 6. Limbo's new events (second session, 2026-11-05)

Heimdall now reads the guest network and file exchange events Limbo started writing today: a guest reaching for this
computer or the home network is a critical alert, a scan or IPv6 a warning, and a guest trying to hand out a file ClamAV
knows is a warning. Reaching for this computer, the home network, or scanning also restricts the guest (its network cut;
only you can release it). Normal guest traffic is never an alert.

```
cd ~/Documents/Github/Labyrinth_OS/packages/pkgbuilds/heimdall-git && makepkg -f
sudo pacman -U "$(ls -t heimdall-git-*.pkg.tar.zst | head -1)"
sudo systemctl restart heimdall
journalctl -u heimdall -n 30 --no-pager | grep -i limbo
```

Builds Heimdall from the newest commit (the r60 package above does not have this) and starts it. The log should say
"Limbo quarantine response enabled" and "watching Limbo event log". This replaces step 1's install if you have not done it yet.

Your config already has `limbo_auto_quarantine: true`, so the restriction is on. To keep the alerts but stop the automatic
restriction, set it to `false` in `/etc/heimdall/config.json` and restart Heimdall.

When a `limbo-exchange` alert says a file was held, Heimdall now keeps a copy in its own malware store by itself (root-only,
never run; Limbo's copy stays; see the answers below). The command still works by hand:

```
sudo heimdalld immunity take-limbo SHA256
```

### Questions (Limbo events; answered 2026-11-05, built 2026-11-07 in `0f80ee0`)

- `limbo-take-auto | y/n`: take each held file into Heimdall's store by itself? Answer: yes. Built: heimdalld leaves the
  request for `heimdall-requests.service` (root), and `heimdall.service` has `ReadWritePaths=-/var/lib/heimdall-requests`.
  Details: `docs/IMMUNITY.md`, "Taking the copy automatically". Needs a rebuilt package (as in section 6).
- `limbo-held-restrict | y/n`: should a guest that tried to hand out a known virus also be restricted? Answer: yes. Built:
  `exchange.held` restricts the guest like a network probe does, and a later stop does not cancel it.

