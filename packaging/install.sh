#!/bin/sh
# packaging/install.sh DESTDIR [private-mic|multilink|yara-check]: install into DESTDIR the files of one of Heimdall's four
# packages.
#   (no second argument)  heimdall-git: Heimdall (an already built ./heimdalld) and everything that comes with it.
#   private-mic           heimdall-private-mic-git: the private microphone and heimdall-scrub (docs/LOCATION_SOUNDS.md), and
#                         the privacy pack (docs/PRIVACY_PACK.md), built in rust/ (cargo build --release --locked
#                         -p heimdall-scrub -p heimdall-scrub-ladspa -p heimdall-privacy).
#   multilink             heimdall-multilink-git: several internet connections at once (docs/MULTILINK.md), built in rust/
#                         (cargo build --release --locked -p heimdall-multilink).
#   yara-check            heimdall-yara-check-git: YARA-X's compile check of rule drafts (docs/IMMUNITY.md, "Rules"), built
#                         in rust/yara-check, a workspace of its own (cargo build --release --locked).
# Every package recipe (Labyrinth's heimdall-git, heimdall-private-mic-git, heimdall-multilink-git and
# heimdall-yara-check-git, packaging/arch/, packaging/arch-private-mic/, packaging/arch-multilink/ and
# packaging/arch-yara-check/)
# calls this one script, so the list of files lives in one place: change it here and every system gets it. No file is in
# two lists.
set -eu
d=${1:?usage: packaging/install.sh DESTDIR [private-mic|multilink|yara-check]}
part=${2:-heimdall}
p=packaging
i() { install -D -m "$1" "$2" "$d/$3"; }
l() { mkdir -p "$d/$(dirname "$2")"; ln -sfn "$1" "$d/$2"; }

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
  i 644 docs/VOICE_DISGUISE.md                   usr/share/doc/heimdall-private-mic/VOICE_DISGUISE.md
  # the privacy pack (docs/PRIVACY_PACK.md): the downloads guard (a user service, on for every account) and Remove hidden
  # info; built in rust/ (cargo build --release --locked -p heimdall-privacy)
  i 755 $r/heimdall-fileguard                    usr/bin/heimdall-fileguard
  i 755 $r/heimdall-strip                        usr/bin/heimdall-strip
  i 644 $p/privacy-pack/heimdall-fileguard.service usr/lib/systemd/user/heimdall-fileguard.service
  install -d "$d/usr/lib/systemd/user/graphical-session.target.wants"
  ln -sfn ../heimdall-fileguard.service "$d/usr/lib/systemd/user/graphical-session.target.wants/heimdall-fileguard.service"
  i 644 docs/PRIVACY_PACK.md                     usr/share/doc/heimdall-private-mic/PRIVACY_PACK.md
  exit 0
fi
if [ "$part" = multilink ]; then
  # off until switched on (Settings, or `sudo heimdall-multilink on`): the unit is not enabled by the package
  i 755 rust/target/release/heimdall-multilink   usr/bin/heimdall-multilink
  i 644 $p/multilink/heimdall-multilink.service  usr/lib/systemd/system/heimdall-multilink.service
  i 644 $p/multilink/org.heimdall.multilink.policy usr/share/polkit-1/actions/org.heimdall.multilink.policy
  i 644 LICENSE                                  usr/share/licenses/heimdall-multilink/LICENSE
  i 644 docs/MULTILINK.md                        usr/share/doc/heimdall-multilink/MULTILINK.md
  exit 0
fi
if [ "$part" = yara-check ]; then
  # heimdalld runs it, when it is there, as a rule draft is kept and tested; nothing starts it otherwise
  i 755 rust/yara-check/target/release/heimdall-yara-check usr/bin/heimdall-yara-check
  i 644 LICENSE                                  usr/share/licenses/heimdall-yara-check/LICENSE
  i 644 rust/yara-check/NOTICE                   usr/share/licenses/heimdall-yara-check/NOTICE.yara-x
  exit 0
fi
[ "$part" = heimdall ] || { echo "packaging/install.sh: unknown part $part" >&2; exit 2; }

i 755 heimdalld                                  usr/bin/heimdalld
# The programs that were shell scripts (heimdall-intel-update, heimdall-dns-blocklist, heimdall-enable-defaults, the
# dispatcher 91-heimdall-netid) are the Rust heimdalld under their names: links to it (docs/RUST_CLI.md, "Shell programs").
# Only the Rust heimdalld answers to them (stage 1 of the switch, docs/RUST_SWITCH.md): started as heimdall-dns-blocklist
# without arguments it prints that program's usage and nothing else; anything else stops the build here, so a package
# never ships links to the Go binary.
l heimdalld                                      usr/bin/heimdall-dns-blocklist
if ! "$d/usr/bin/heimdall-dns-blocklist" 2>/dev/null | grep -q '^heimdall-dns-blocklist: block known'; then
  echo "install.sh: usr/bin/heimdalld is not the Rust heimdalld, which the shell programs' links need: merge this with stage 1 of the switch (docs/RUST_SWITCH.md)" >&2
  exit 1
fi
i 644 LICENSE                                    usr/share/licenses/heimdall/LICENSE
# MITRE's terms for the ATT&CK table compiled into heimdalld (docs/ATTACK.md)
i 644 NOTICE-ATTACK                              usr/share/licenses/heimdall/NOTICE-ATTACK
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
l heimdalld                                      usr/bin/heimdall-intel-update
i 644 $p/arch/heimdall-intel-update.service      usr/lib/systemd/system/heimdall-intel-update.service
i 644 $p/arch/heimdall-intel-update.timer        usr/lib/systemd/system/heimdall-intel-update.timer

# the Wi-Fi safety check, run by NetworkManager on every Wi-Fi connection
i 755 $p/arch/heimdall-wifi-check                usr/bin/heimdall-wifi-check
i 644 $p/arch/heimdall-wifi-check@.service       usr/lib/systemd/system/heimdall-wifi-check@.service
i 755 $p/net/dispatcher.d/90-heimdall-wifi       usr/lib/NetworkManager/dispatcher.d/90-heimdall-wifi
# (NetworkManager follows a link to a root-owned program and starts it under the link's name)
l /usr/bin/heimdalld                             usr/lib/NetworkManager/dispatcher.d/91-heimdall-netid

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
# Settings' "Discoverable" switch for a Wi-Fi network (heimdall-wifi-guard discoverable on|off --uuid UUID, as root)
i 644 $p/net/units/heimdall-wifi-discoverable-on@.service  usr/lib/systemd/system/heimdall-wifi-discoverable-on@.service
i 644 $p/net/units/heimdall-wifi-discoverable-off@.service usr/lib/systemd/system/heimdall-wifi-discoverable-off@.service
i 644 docs/WIFI_TRUST.md                         usr/share/doc/heimdall/WIFI_TRUST.md

# the DNS block list (NetworkManager's local DNS cache refuses malware, phishing and scam domains)
# (usr/bin/heimdall-dns-blocklist: the link made beside heimdalld above)
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
l heimdalld                                      usr/bin/heimdall-enable-defaults
i 644 $p/net/heimdall-install.hook               usr/share/libalpm/hooks/heimdall-install.hook
