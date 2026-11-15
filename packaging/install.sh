#!/bin/sh
# packaging/install.sh DESTDIR [private-mic]: install into DESTDIR the files of one of Heimdall's two packages.
#   (no second argument)  heimdall-git: Heimdall (an already built ./heimdalld) and everything that comes with it.
#   private-mic           heimdall-private-mic-git: the private microphone and heimdall-scrub (docs/LOCATION_SOUNDS.md),
#                         built in rust/ (cargo build --release --locked -p heimdall-scrub -p heimdall-scrub-ladspa).
# Every package recipe (Labyrinth's heimdall-git and heimdall-private-mic-git, packaging/arch/ and packaging/arch-private-mic/)
# calls this one script, so the list of files lives in one place: change it here and every system gets it. No file is in
# both lists.
set -eu
d=${1:?usage: packaging/install.sh DESTDIR [private-mic]}
part=${2:-heimdall}
p=packaging
i() { install -D -m "$1" "$2" "$d/$3"; }

if [ "$part" = private-mic ]; then
  # every install of Labyrinth OS and LykanOS gets this, with or without Heimdall
  r=rust/target/release
  i 755 $r/heimdall-scrub                        usr/bin/heimdall-scrub
  i 755 $r/heimdall-private-mic                  usr/bin/heimdall-private-mic
  i 755 $r/libheimdall_scrub_ladspa.so           usr/lib/ladspa/heimdall-scrub.so
  i 644 $p/privacy/pipewire-private-mic.conf     usr/share/pipewire/pipewire.conf.d/60-heimdall-private-mic.conf
  i 644 $p/privacy/wireplumber-private-mic.conf  usr/share/wireplumber/wireplumber.conf.d/60-heimdall-private-mic.conf
  i 644 $p/privacy/private-mic.lua               usr/share/wireplumber/scripts/heimdall/private-mic.lua
  # the LykanOS-only part: linked into /etc/wireplumber by `heimdall-private-mic os-setup` only where ID=lykanos
  i 644 $p/privacy/wireplumber-private-mic-lykanos.conf usr/share/heimdall-private-mic/lykanos.conf
  i 644 $p/privacy/heimdall-private-mic.hook     usr/share/libalpm/hooks/heimdall-private-mic.hook
  i 644 $p/privacy/heimdall-private-mic-remove.hook usr/share/libalpm/hooks/heimdall-private-mic-remove.hook
  i 644 LICENSE                                  usr/share/licenses/heimdall-private-mic/LICENSE
  i 644 rust/scrub/NOTICE                        usr/share/licenses/heimdall-private-mic/NOTICE.flyover-scrub
  i 644 docs/LOCATION_SOUNDS.md                  usr/share/doc/heimdall-private-mic/LOCATION_SOUNDS.md
  exit 0
fi
[ "$part" = heimdall ] || { echo "packaging/install.sh: unknown part $part" >&2; exit 2; }

i 755 heimdalld                                  usr/bin/heimdalld
i 644 LICENSE                                    usr/share/licenses/heimdall/LICENSE
i 644 README.md                                  usr/share/doc/heimdall/README.md
i 644 $p/arch/heimdall.service                   usr/lib/systemd/system/heimdall.service
i 644 $p/arch/heimdall.sysusers                  usr/lib/sysusers.d/heimdall.conf
i 644 $p/arch/config.json.example                etc/heimdall/config.json.example
# read access (ACL, read only) to Sarina's session folder, set at boot and as soon as Sarina's service makes the folder
i 644 $p/arch/heimdall-sarina-read.tmpfiles     usr/lib/tmpfiles.d/heimdall-sarina-read.conf
i 644 $p/arch/heimdall-sarina-access.path       usr/lib/systemd/system/heimdall-sarina-access.path
i 644 $p/arch/heimdall-sarina-access.service    usr/lib/systemd/system/heimdall-sarina-access.service
# containment of a compromised AI agent: heimdalld asks, this root unit acts (off until /etc/heimdall/contain.json says so)
i 644 $p/arch/heimdall-contain.path              usr/lib/systemd/system/heimdall-contain.path
i 644 $p/arch/heimdall-contain.service           usr/lib/systemd/system/heimdall-contain.service
# immunity: held files, release requests (proof-checked by root), the daily inventory of programs
i 644 $p/arch/heimdall-requests.path             usr/lib/systemd/system/heimdall-requests.path
i 644 $p/arch/heimdall-requests.service          usr/lib/systemd/system/heimdall-requests.service
i 644 $p/arch/heimdall-requests.tmpfiles         usr/lib/tmpfiles.d/heimdall-requests.conf
i 644 $p/arch/heimdall-inventory.service         usr/lib/systemd/system/heimdall-inventory.service
i 644 $p/arch/heimdall-inventory.timer           usr/lib/systemd/system/heimdall-inventory.timer
i 644 docs/CONTAIN.md                            usr/share/doc/heimdall/CONTAIN.md
i 644 docs/IMMUNITY.md                           usr/share/doc/heimdall/IMMUNITY.md
i 644 docs/AUDITS.md                             usr/share/doc/heimdall/AUDITS.md
i 644 docs/GRANTS.md                             usr/share/doc/heimdall/GRANTS.md
i 644 docs/MESH.md                               usr/share/doc/heimdall/MESH.md
i 644 $p/arch/limbo-integration.conf.example     etc/heimdall/limbo-integration.conf.example
# read-only journal access, for the firewall and SSH-login watch
i 644 $p/arch/heimdall-firewall.conf.example     usr/lib/systemd/system/heimdall.service.d/firewall.conf

# threat lists, the security tracker and the IP databases (downloaded daily, used offline)
i 755 $p/arch/heimdall-intel-update              usr/bin/heimdall-intel-update
i 644 $p/arch/heimdall-intel-update.service      usr/lib/systemd/system/heimdall-intel-update.service
i 644 $p/arch/heimdall-intel-update.timer        usr/lib/systemd/system/heimdall-intel-update.timer

# the Wi-Fi safety check, run by NetworkManager on every Wi-Fi connection
i 755 $p/arch/heimdall-wifi-check                usr/bin/heimdall-wifi-check
i 644 $p/arch/heimdall-wifi-check@.service       usr/lib/systemd/system/heimdall-wifi-check@.service
i 755 $p/net/dispatcher.d/90-heimdall-wifi       usr/lib/NetworkManager/dispatcher.d/90-heimdall-wifi

# the device list of trusted home networks (every 5 minutes; Settings > Wi-Fi & Network > Devices; docs/DEVICES.md)
i 644 $p/arch/heimdall-lan-scan.service          usr/lib/systemd/system/heimdall-lan-scan.service
i 644 $p/arch/heimdall-lan-scan.timer            usr/lib/systemd/system/heimdall-lan-scan.timer
i 644 $p/arch/heimdall-lan-scan.rules            usr/share/polkit-1/rules.d/50-heimdall-lan-scan.rules
i 644 docs/DEVICES.md                            usr/share/doc/heimdall/DEVICES.md
i 644 docs/WIFI_HEALTH.md                        usr/share/doc/heimdall/WIFI_HEALTH.md

# trusted networks, the VPN with its kill switch, and a quiet computer on untrusted networks
i 755 $p/net/heimdall-wifi-guard                 usr/bin/heimdall-wifi-guard
i 755 $p/net/dispatcher.d/50-heimdall-wifi-guard usr/lib/NetworkManager/dispatcher.d/50-heimdall-wifi-guard
i 755 $p/net/dispatcher.d/pre-up.d/50-heimdall-wifi-guard usr/lib/NetworkManager/dispatcher.d/pre-up.d/50-heimdall-wifi-guard
i 644 $p/net/heimdall-wifi-privacy.conf          usr/lib/NetworkManager/conf.d/heimdall-wifi-privacy.conf

# the DNS block list (NetworkManager's local DNS cache refuses malware, phishing and scam domains)
i 755 $p/net/heimdall-dns-blocklist              usr/bin/heimdall-dns-blocklist
i 644 $p/net/heimdall-dns.conf                   usr/lib/NetworkManager/conf.d/heimdall-dns.conf
i 644 $p/net/heimdall-blocklist.conf             etc/NetworkManager/dnsmasq.d/heimdall-blocklist.conf
i 644 $p/net/heimdall-rebind.conf                etc/NetworkManager/dnsmasq.d/heimdall-rebind.conf
i 644 $p/net/dns-allow.txt                       etc/heimdall/dns-allow.txt
i 644 $p/net/heimdall-dns-block.tmpfiles         usr/lib/tmpfiles.d/heimdall-dns.conf
i 644 $p/net/units/heimdall-dns-blocklist.service usr/lib/systemd/system/heimdall-dns-blocklist.service
i 644 $p/net/units/heimdall-dns-blocklist.timer  usr/lib/systemd/system/heimdall-dns-blocklist.timer

# the desktop notification of Wi-Fi verdicts and guard events
i 755 $p/net/heimdall-wifi-notify                usr/bin/heimdall-wifi-notify
i 644 $p/net/user-units/heimdall-wifi-notify.path    usr/lib/systemd/user/heimdall-wifi-notify.path
i 644 $p/net/user-units/heimdall-wifi-notify.service usr/lib/systemd/user/heimdall-wifi-notify.service

# switched on by itself on a fresh install (never again on upgrades, so the owner's choices stay)
i 755 $p/net/heimdall-enable-defaults            usr/bin/heimdall-enable-defaults
i 644 $p/net/heimdall-install.hook               usr/share/libalpm/hooks/heimdall-install.hook
