# Remote access watch

Malware that wants to stay on a computer usually brings its own way back in: a tunnel (ngrok, cloudflared, frp, chisel), a
mesh VPN (Tailscale, ZeroTier, Netbird), a remote desktop (AnyDesk, RustDesk, a VNC server) or a command-and-control implant
(Sliver, Merlin). Heimdall watches for all of these whether or not the owner ever installed one, and says which tool it is.

## What is watched (phase 1)

| Signal | How | Cost |
|---|---|---|
| A package of a known tool is installed | `rasource` reads the names in `/var/lib/pacman/local` when that folder changes | one `stat` every 15 s |
| A tool's network interface appears (`tailscale0`, `zt*`, `wt0`, ...) | `rasource` lists `/sys/class/net` | one `readdir` every 15 s |
| A new WireGuard or tun interface no catalog entry explains | same; interfaces present at start count as the computer's own | same |
| A program of a known tool makes a connection | `ConnWatcher` names the program behind each new connection (`/proc/PID/exe`) | only on new connections |
| The same, renamed (`systemd-helper` that is really chisel) | Go build info in the binary (`debug/buildinfo`), cached by path, size and time | read once per binary |

The catalog is `internal/remoteaccess/remote-access.json`, built into heimdalld. Each entry gives package names, program
names, interface patterns, Go module paths and a kind (`mesh-vpn`, `tunnel`, `remote-desktop`, `anonymizer`, `c2`).

## Alerts

- A tool that is not approved: **critical**, with what was seen and where.
- An approved tool: **info** (it is expected, but a record is kept).
- A `c2` implant: always **critical**. It cannot be approved.
- A new tunnel interface nothing explains: **warning**.
- One alert per tool and signal per hour.

Nothing is stopped or removed in phase 1. Holding a tool (stop its service, cut its connections, quarantine the binary) comes
later, behind its own switch, and only after the watch has run for a while without false alarms.

## Approving a tool you installed yourself

```
heimdalld remote list                 # the catalog, and what is approved
sudo heimdalld remote approve tailscale
sudo heimdalld remote forget tailscale
```

Approvals live in `/etc/heimdall/remote-access-approved.json` (root only). heimdalld reads the file again when it changes.

## Using Tailscale safely (when the owner adopts it)

The "Tailworm" flaws of October 2026 need Tailscale SSH with forwarding turned on. The profile below leaves out every part
that was attacked, and keeps the part that is useful (reaching home from a phone or laptop):

```
sudo tailscale up --ssh=false --shields-up --accept-routes=false --accept-dns=true
sudo tailscale set --auto-update
sudo heimdalld remote approve tailscale
```

- **No Tailscale SSH.** If remote shell access is ever needed, use OpenSSH bound to the tailnet address with keys only.
- **No Funnel, no Serve** (they put a local service on the internet or the tailnet).
- **`--shields-up`** on desktops: other tailnet devices cannot open connections to this one unless that is changed on purpose.
- **Tailnet Lock** on, so a stolen or compromised coordination server cannot add a device.
- **ACLs default-deny** in the admin console; allow only the device pairs that need to talk.
- Keep it updated (`--auto-update`), and check the version against Heimdall's intel when a new advisory appears.

### Without Tailscale's servers

- **Plain WireGuard** (`wg-quick`, in the kernel): one small configuration per device, no coordination server, no extra
  daemon. Best when there are only a few devices. Heimdall's new-tunnel warning will fire once for the interface; approve it
  by name in the catalog's own-setup entry when that is added.
- **Headscale** (self-hosted coordination server) with the official clients: the Tailscale experience without the hosted
  service, but the same client and its flaws, so the profile above still applies.

## Next phases

1. Footholds: new services, timers, autostart entries, cron jobs, `.pth` files and `ld.so.preload` entries that point at a
   tool or at a hidden or temporary program.
2. Kernel: a module loaded that was never loaded before (`ksmbd`, `nvmet*`, `rds`, ...), raw-packet and BPF listeners
   (backdoors with no open port), shells whose input is a network socket.
3. Tailscale posture, once installed: SSH, Funnel and Serve state, version against advisories, new peers.
4. Holds, behind an owner switch: stop and disable the tool's service, cut its connections, quarantine its binary, all
   reversible with `heimdalld respond release`.
