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
