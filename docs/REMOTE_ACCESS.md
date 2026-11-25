# Remote access watch

Malware that wants to stay on a computer usually brings its own way back in: a tunnel (ngrok, cloudflared, frp, chisel), a
mesh VPN (Tailscale, ZeroTier, Netbird), a remote desktop (AnyDesk, RustDesk, Sunshine, a VNC server) or a command-and-control implant
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

## The kernel's side (phase 2, HEI-12)

A way in does not need a program with an open port. `rasource` also looks, every 15 seconds, at:

| Signal | How | Alert |
|---|---|---|
| A kernel module that makes the kernel itself serve the network is loaded: ksmbd (SMB), nfsd (NFS), an NVMe over Fabrics or iSCSI target, USB/IP (`usbip_host`), RDS | one read of `/proc/modules`, matched against the catalog's `modules` (kind `kernel`); one loaded before Heimdall started counts too | **critical** unless approved (`heimdalld remote approve ksmbd`), then info |
| A program holds a raw packet socket: it sees every packet and can wait for a secret one with no open port, as BPFDoor does | `/proc/net/packet`; the owner is looked up (a walk of `/proc/*/fd`) only for a socket not seen before | **warning**, except the usual holders: DHCP clients and servers, Wi-Fi supplicants, packet captures (`tcpdump`, `dumpcap`, ...), `nmap`, `arp-scan`, `lldpd` |
| A shell (`sh`, `bash`, `dash`, `zsh`, ...) whose input is a TCP or UDP socket: a reverse shell | each process's name, then the shell's `fd/0`, looked up in `/proc/net/{tcp,udp}{,6}` | **critical**, never approvable |

Other users' processes (a root service's packet socket, a shell started by a web server) are seen only with the connection
watcher's rights (`CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, `packaging/arch/heimdall-connwatch.conf.example`); without
them a socket whose owner cannot be seen is passed over, never guessed.

## Alerts

- A tool that is not approved: **critical**, with what was seen and where.
- An approved tool: **info** (it is expected, but a record is kept).
- A `c2` implant: always **critical**. It cannot be approved.
- A program that only *contains* a tool's code (ngrok's library, Tailscale's tsnet): **warning**. Some of these really open a
  tunnel; others only borrow a small utility package.
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

## Known limitations

- Footholds are not watched: new services, timers, autostart entries, cron jobs, `.pth` files and `ld.so.preload` entries that
  point at a tool or at a hidden or temporary program.
- Of the kernel's side, eBPF programs attached to an interface (XDP, tc) are not seen: listing them needs `CAP_BPF` or root,
  which Heimdall's daemon does not have. A raw packet socket with a filter (the classic BPF that BPFDoor uses) is seen.
- A reverse shell that is not a shell (a Python or Perl one-liner reading a socket) is not recognised as one.
- Tailscale's own state (SSH, Funnel and Serve, its version against advisories, new peers) is not read.
- Heimdall reports a remote-access tool; it does not stop its service, cut its connections or quarantine its binary.
