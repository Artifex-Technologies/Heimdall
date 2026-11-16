# Audits: known holes in the kernel and packages, and settings that could be safer

Heimdall checks three things every six hours, offline, and reports each finding once (again when it changes). Nothing is changed by
itself: each finding says how to fix it, and Sarina (when installed) explains the findings and proposes the fix to the owner.

| detector | what | where the data comes from |
| --- | --- | --- |
| `package-vulnerability` | an installed package version with a known vulnerability | Arch's security tracker, daily |
| `kernel-vulnerability` | an installed kernel with known holes that a newer kernel fixes | the kernel CVE team's records (osv.dev), with CISA's list of vulnerabilities exploited in the wild, weekly |
| `hardening` | a setting that leaves a known kind of hole open where closing it costs nothing noticeable | this computer (/dev, /sys, /proc) |

`heimdall-intel-update` does every download (heimdalld never connects off the machine): only public lists are fetched, nothing
about this computer is sent.

## Kernel holes

The kernel's CVE team files a CVE for nearly every fixed bug, so only holes **with a fix** are reported, per installed kernel (the
running one and the others, such as the LTS fallback): how many, the worst, which are fixed on the kernel's own line (an update of
that kernel package closes them) and which only in newer lines (booting the newer kernel closes them). Severity: critical only for a
hole known to be exploited in the wild in the running kernel; otherwise a warning for the running kernel and info for the others.

```
sudo heimdalld kernel-check [--all]      # per installed kernel: the holes an update fixes (! = exploited in the wild)
```

Distribution kernels (CachyOS) follow the stable releases closely, so the version decides; a kernel that carries a fix early is
still listed until its version passes the fixed one.

## Hardening checks

| check | fix | cost |
| --- | --- | --- |
| `/dev/kvm` writable by every account | `0660`, group `kvm`, users who run VMs in that group | none (sign out and in once) |
| KVM nested virtualisation on | `options kvm_intel nested=0` (or kvm_amd) | VMs inside VMs stop working |
| `dev.tty.ldisc_autoload = 1` | `0` | none on a desktop |
| `kernel.kptr_restrict = 0` | `1` | none |
| `fs.protected_fifos`, `fs.protected_regular` below 2 | `2` | none |
| `net.core.bpf_jit_harden` below 2 (when the kernel has it) | `2` | a little BPF speed |

Example: Januscape (CVE-2026-53359, a KVM guest-to-host escape, also a local root exploit where `/dev/kvm` is writable by everyone)
is reported by `kernel-vulnerability` on a kernel before 6.1.177 / 6.6.144 / 6.12.95 / 6.18.38 / 7.1.3 / 7.2, and the two KVM
hardening checks close the paths it needs even before the update.

### The SSH server check

Added 2026-11-16 after SSHole (CVE-2026-123158, disclosed 2026-11-05): OpenSSH before 10.6p2, built against musl, without PAM
and with password logins on, accepts an over-long password for an account whose stored hash is `*` (locked). glibc builds and
PAM logins were never open to it, but an SSH server that takes passwords is worth knowing about on every computer Heimdall
watches (Labyrinth OS, LykanOS, a Raspberry Pi). Read-only and offline; nothing is changed and nothing is blocked, I decide.

What it reads: whether something listens on sshd's ports (`/proc/net/tcp{,6}`; `Port` lines, default 22), the start links
(`/etc/systemd/system/*.wants/{sshd,ssh}.{service,socket}`, OpenRC's `/etc/runlevels/*/sshd`), the settings (`sshd -T` when
Heimdall runs as root on the real system; otherwise `/etc/ssh/sshd_config` with `Include` followed, the first value of a
keyword winning as in sshd, and a `yes` inside any `Match` block counted as on), and the sshd program file itself: its version
string (the newest `OpenSSH_x.ypN` in it) and its ELF interpreter (`ld-musl` = musl, `ld-linux` = glibc). Dropbear: its start
links and whether `-s` (no passwords) is in `/etc/conf.d/dropbear` or `/etc/default/dropbear`.

| check (`check` field) | level | fix |
| --- | --- | --- |
| `ssh-sshole`: OpenSSH below 10.6p2 + musl + `UsePAM no` + `PasswordAuthentication yes` | critical when listening or started at boot, info when only installed; field `cve` | update OpenSSH; until then `PasswordAuthentication no` |
| `ssh-password-login`: `PasswordAuthentication yes`, or `KbdInteractiveAuthentication yes` with `UsePAM yes` | warning when listening or started at boot, info when only installed | `PasswordAuthentication no`, `KbdInteractiveAuthentication no`; use keys |
| `ssh-root-password`: the above and `PermitRootLogin yes` | as above | `PermitRootLogin prohibit-password` |
| `ssh-empty-passwords`: the above and `PermitEmptyPasswords yes` | as above | `PermitEmptyPasswords no` |
| `ssh-settings-unread`: a running sshd whose config Heimdall may not read | info | check with `sudo sshd -T` |
| `ssh-dropbear-password`: dropbear without `-s` | warning when started at boot, info when only installed | `-s` in its options |

The alert fields (`check`, `now`, `why`, `fix`, `level`, and `cve` on `ssh-sshole` only) are stable names for readers;
`GET /v1/audit`'s `hardening` entries gain `cve` the same way (left out when empty). The `hardening` detector makes a `critical`
level a critical alert; every other gap stays a warning or info as before.
