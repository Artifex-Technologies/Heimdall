# Containment: stopping a compromised AI agent

When Sarina (or anything posing as Sarina) may be compromised, Heimdall stops Sarina in steps. Each step goes further only when the one
before did not hold.

0. **Evidence.** Before anything is stopped, Heimdall saves what is needed to learn what happened, in a root-only folder
   (`/var/lib/heimdall-evidence/<time>/`, `sudo heimdalld contain evidence` lists them): every process (Sarina's with the SHA-256
   of the program actually running, its memory map, open files and environment with secrets hidden), the network connections,
   what is on the graphics card and in the model server, the last hour of the system log, copies of Sarina's behaviour files that are
   not as approved, and Sarina's newest sessions. Capped at 256 MiB; it takes seconds.
1. **Contain.** A lock (`/etc/heimdall/contained`) is written first, so a Sarina that is just starting refuses. Then Sarina's service,
   timers and every Sarina process are stopped, and the AI models are unloaded from the graphics card (Ollama, `keep_alive 0`).
   The lock survives a restart: nothing comes back until the owner releases Sarina.
2. **Check.** A minute later: is a Sarina process back, or a model loaded again? If not, containment held, and the desktop, games
   and everything else keep running.
3. **Emergency (the last resort).** The approved behaviour files are put back from the known-good copies (`heimdalld trust
   restore`, see TRUST.md), so a file the attacker changed cannot corrupt Sarina when Sarina comes back. The login screen (and with it the
   desktop) and the model server are stopped, every program using the graphics card is killed (games too), an NVIDIA card is reset
   (its memory is cleared), and the computer restarts. The lock stays, so the restart does not bring Sarina back.

## Who does what

`heimdalld` runs unprivileged. On a critical finding about the agents it only writes a request
(`/var/lib/heimdall/contain-request.json`); the root unit `heimdall-contain.path` / `.service` carries it out. The findings that
count: an unapproved change to one of the agents' behaviour files (trust in watch or enforce mode), and a session that kept asking
for tools its tier does not allow. An injection phrase alone does not: it is often only text Sarina read. At most one request every
ten minutes, none while the lock is there.

## Switches (`/etc/heimdall/contain.json`, root-owned)

```json
{ "auto_contain": false, "auto_emergency": false }
```

Missing means both off, which is the default (while Sarina and Heimdall are still being trained). `auto_contain` lets Heimdall
contain by itself; `auto_emergency` also lets it take the emergency step when containment did not hold. Without it the owner is told
and decides.

## Commands

```
heimdalld contain status                         contained or not, and the switches
sudo heimdalld contain now [--reason R] [--escalate]   contain by hand (--escalate: the emergency follows if it did not hold)
sudo heimdalld contain emergency --yes           the last resort, by hand
sudo heimdalld contain release                   restore the approved files, then lift the lock
```

Settings > Security shows the lock with a **Restore and release** button: it asks for the owner's password and runs `release`.

## Limits

- A program running as root can undo all of this; the protection is against what runs as the user and as Sarina.
- Clearing the graphics card's memory works by a reset on NVIDIA cards (`nvidia-smi --gpu-reset`). Other cards are cleared by the
  restart.
- `release` never deletes planted files the signed list does not know; the alert names them.
