#!/bin/sh
# packaging/install.sh DESTDIR: install Heimdall (an already built ./heimdalld) and everything that comes with it into DESTDIR.
# Every package recipe (Labyrinth's and Niflheim's heimdall-git, packaging/arch/PKGBUILD) calls this one script, so the list of
# files lives in one place: change it here and every system gets it.
set -eu
d=${1:?usage: packaging/install.sh DESTDIR}
p=packaging
i() { install -D -m "$1" "$2" "$d/$3"; }

i 755 heimdalld                                  usr/bin/heimdalld
i 644 LICENSE                                    usr/share/licenses/heimdall/LICENSE
i 644 README.md                                  usr/share/doc/heimdall/README.md
i 644 $p/arch/heimdall.service                   usr/lib/systemd/system/heimdall.service
i 644 $p/arch/heimdall.sysusers                  usr/lib/sysusers.d/heimdall.conf
i 644 $p/arch/config.json.example                etc/heimdall/config.json.example
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

# trusted networks, the VPN with its kill switch, and a quiet computer on untrusted networks
i 755 $p/net/heimdall-wifi-guard                 usr/bin/heimdall-wifi-guard
i 755 $p/net/dispatcher.d/50-heimdall-wifi-guard usr/lib/NetworkManager/dispatcher.d/50-heimdall-wifi-guard
i 755 $p/net/dispatcher.d/pre-up.d/50-heimdall-wifi-guard usr/lib/NetworkManager/dispatcher.d/pre-up.d/50-heimdall-wifi-guard
i 644 $p/net/heimdall-wifi-privacy.conf          usr/lib/NetworkManager/conf.d/heimdall-wifi-privacy.conf

# the DNS block list (NetworkManager's local DNS cache refuses malware, phishing and scam domains)
i 755 $p/net/heimdall-dns-blocklist              usr/bin/heimdall-dns-blocklist
i 644 $p/net/heimdall-dns.conf                   usr/lib/NetworkManager/conf.d/heimdall-dns.conf
i 644 $p/net/heimdall-blocklist.conf             etc/NetworkManager/dnsmasq.d/heimdall-blocklist.conf
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
