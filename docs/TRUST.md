# Trust: the signed list of the AI agents' behaviour files

**Why.** Sarina's behaviour is set by files: her rules (`~/.sarina/policy.json`), her tool connections (`mcp.json`), her skills
and skill collections (`~/.sarina/skills`, `skills.json`, `vendor/`), her agent profiles (`~/.sarina/agents`), and the settings
of her service (`/etc/sarina`) and of Heimdall (`/etc/heimdall/config.json`). Most of them are writable by the user's account, so
any program running as the user (an AI-aimed virus, a poisoned download) could change how she behaves by editing a Markdown file.

**What.** The owner keeps a list of those files with the SHA-256 of the content they approved, signed with an Ed25519 key that only
root can read. Approving needs the owner's password (sudo); a program running as the user cannot sign anything. Anyone can check a
file against the list.

- **Heimdall** watches the listed files and folders. A change that matches the signed list is an *info* finding (an approved change);
  a change, a new file in a watched folder (a planted skill) or a deletion that does not match is *critical*. Changes are judged after
  a two-minute grace, so a change made and then signed is quiet.
- **Sarina** (in enforce mode) checks every behaviour file before using it: an unapproved skill, section, agent or tool connection
  file is not used, and an unapproved rules file (policy.json) stops her, since ignoring it could drop the owner's own restrictions.
  Files under `/usr` belong to installed packages and are not checked.
- **Known-good copies.** Every signed content is also kept, root-only. `heimdalld trust restore` puts back what was approved, so after
  an attack the agents come back exactly as they were approved, without anything to relearn.

Nothing here hides anything from the owner: every file stays plain text and readable; the protection is that changes need the
owner's signature.

## Modes (`/etc/heimdall/trust/mode`, root-owned)

| mode | Heimdall | Sarina |
| --- | --- | --- |
| `off` (default) | watches only its own list (`fim_paths`), as before | uses every file |
| `watch` | also the agents' files: unsigned change = critical alert, signed = info | uses every file |
| `enforce` | as watch | refuses unapproved files |

`off` while the agents are still being trained and their files change daily; `watch` once they settle; `enforce` when they are done.

## Commands

```
sudo heimdalld trust init                 # the signing key, and the default watch list for the user who ran sudo
sudo heimdalld trust sign --watched       # approve everything watched as it is now (the starting point)
sudo heimdalld trust mode watch           # restarts heimdalld so it watches the agents' files
heimdalld trust status                    # mode, signed files, what is watched
heimdalld trust verify                    # each watched file: ok, CHANGED, MISSING or UNSIGNED (exit 1 if any is not ok)
sudo heimdalld trust sign ~/.sarina/skills/my-skill    # approve a change you made
sudo heimdalld trust forget PATH          # take a file off the list (after deleting it on purpose)
sudo heimdalld trust restore [PATH]       # put back the approved content of changed or deleted files
sudo heimdalld trust watch add|remove PATH
```

`restore` never deletes a file the list does not know (a planted file): the alert names it, and removing it is the owner's decision.

## Files (`/etc/heimdall/trust`)

`owner.key` (0600 root), `owner.pub`, `manifest.json` + `manifest.sig` (the list and its signature over the exact bytes), `mode`,
`watch.json`, `approved/<sha256>` (0700 root: the known-good copies).

## Limits

- Root defeats it: a program running as root can sign. The protection is against everything that runs as the user, which is where
  an infection usually starts; the root password and Heimdall's other detectors guard the rest.
- The signing key is a file readable by root. Sealing it with the TPM (`systemd-creds`) is the next step; a lost key means signing
  everything again after `trust init` on a new key (nothing is lost but the old signatures).
- Heimdall reads the watched files with its read-only capability (`CAP_DAC_READ_SEARCH`, see the unit); it cannot write them.
