# Trusting a Wi-Fi network

Marking a network as trusted stops the "untrusted" notices on it. That is all it does. Every protection stays on, and Heimdall
keeps reporting devices that try to reach this computer. Opening up for a home network is a separate choice.

All examples use made-up names.

## The three levels

| Level | How you set it | What changes compared with untrusted |
|---|---|---|
| **untrusted** (every network you have not marked) | – | Nothing: all protections are on. The VPN connects if one is set up, and the Wi-Fi is dropped if it cannot. |
| **trusted** | `sudo heimdall-wifi-guard trust` while on the network | **Notices only.** There are no "untrusted" or "no VPN" notices. Nothing is loosened: the firewall, not announcing this computer, its own hardware address for the network, no computer name sent, the router warning (unless the router is a phone hotspot, below), and the VPN if one is set up all stay. |
| **home** | `sudo heimdall-wifi-guard trust --home` | Everything `trust` did before the levels: the device list (`heimdalld lan scan`), discovery (Avahi), no router watch and no VPN. Add `--real-address` to also send the computer's real hardware address and name there. |

`sudo heimdall-wifi-guard untrust NAME` returns a network to untrusted. Its profile goes back to a private address with no
name sent. On the network connected now it takes effect at once (the quiet table, Avahi off); the VPN and the private address
apply from the next connection, and it says so. `heimdall-wifi-guard status` shows each network's level, what is in force on the current one, what that network
can still see, and whether devices reaching this computer are reported. `trust` takes only `--home`, `--real-address` and
`--uuid UUID`; any other word stops it with nothing changed.

Making a home network only trusted (`trust` on it) closes it up at once: the quiet table is loaded and Avahi is stopped. Its
private hardware address, no name sent and the VPN apply from the next connection, so `trust` asks you to reconnect.

The firewall (ufw) is never changed at any level. Heimdall only reads it: that it is on, that it drops incoming connections, and
which ports its own rules let in.

### What changes on a computer that does not use the new commands

On the **desktop** (wired), nothing: the guard and the check act on Wi-Fi only, and the quiet table matches Wi-Fi interfaces
only. An entry in `/etc/heimdall/wifi-trusted.json` from before the levels (no `level` key) is **home**, exactly as before.

On a **laptop**, even without a new command:
- the quiet table is loaded on every Wi-Fi network but home, and its profile gets `connection.llmnr no` and `connection.mdns no`;
- the "no VPN" notice still comes on every connection to an untrusted network, as before (the owner's choice); a trusted
  network never shows it;
- a home entry from before the levels whose router is a different one counts as trusted (it was untrusted). It keeps every
  protection and the VPN, and you get one notice a day instead of one per connection. The check's router warning stays as it
  was;
- DNS answers outside a site's own network are decided by the site's certificate (below);
- `results.jsonl` is made mode 0640 and records how many other devices were heard, not who.

## How a trusted network is recognized

A trusted network is matched by its saved NetworkManager profile, the network name in it, and its lock (WPA2-Personal
`wpa-psk` or WPA3-Personal `sae`). It is not matched by the router's hardware address. NetworkManager brings the profile up only
after the access point has proved it knows the password: through WPA2's 4-way handshake or WPA3's SAE exchange. A look-alike
network without the password never gets that far.

`trust` also keeps a fingerprint of the profile's saved password (sha256 of the profile and the password) in
`/etc/heimdall/wifi-trusted-keys.json`, readable by root only. Editing a saved profile to another password is all it takes to
make it join somebody else's network of the same name. The guard compares the fingerprint each time the network comes up, and
a profile with another password is untrusted and you are told. A password kept in the desktop's keyring instead of by the
system is not readable by root, so nothing is kept or compared for it.

This is why a **phone hotspot** stays trusted when it changes its hardware address on restart. The check's router warning
("the router's hardware address is different from the last time") is "ok" only when all of these hold: the network is trusted
at the trusted level (not home, not an entry from before the levels), the guard did not find its profile changed (its saved
password), and the new router address is one a device made up (locally administered, as phone hotspots use). Anywhere else a new router address is still a warning: another device on the
network taking the router's place looks the same.

What this does not cover:
- Anyone who knows the password can run a copy of the network.
- Under WPA2, someone with the password who captures the handshake can read traffic, and a weak password can be cracked
  offline. WPA3 has neither weakness. Use a long password, and WPA3 if the phone offers it.

**Never trustable:** open networks, Enhanced Open (OWE), WEP and enterprise (EAP) networks. None of them has a password that
every device must prove it knows. `trust` refuses them.

A **home** network is also bound to its router's hardware address, because the device list must never sweep a stranger's
network. When the router of a home network is a different one, the network counts only as trusted. The device list pauses,
the computer stays private, and you are told once a day. If you replaced the router, run `trust --home` again. If it is a phone
hotspot trusted before the levels, run `trust` (trusted, not home) on it.

The device list reads the same file: only an entry with no `level`, or with `"level": "home"`, is looked around. `"trusted"`
gives the status `not_home`; any other value (empty, null, a number) counts as untrusted (`not_trusted`), as the guard and the
check count it.

## What Heimdall still tells you on a trusted network

- **unsafe** (critical): any sign of an attack, at every level. That covers ARP spoofing, DNS answers that lead to a
  certificate this computer does not trust, intercepted HTTPS, changed web pages, and a look-alike network with different
  security nearby.
- **A network with the name of one you trust but not its lock** (critical), for example an open copy of your hotspot.
- **A device tried to reach this computer** (`lan-watch` warning), on every network but home. This covers a device on the
  network itself (a private or link-local address) starting a connection to this computer (a TCP SYN), sending it a new UDP
  packet (a direct question such as NetBIOS's "what is your name", unicast mDNS, LLMNR or SNMP) or pinging it. Packets of
  connections this computer made, late or stray packets, and anything from an internet address are never reported. Each device
  is reported once an hour, and at most 5 devices an hour; past that, one more warning says that more devices tried within the
  hour (many at once can be one device sweeping the network with made-up addresses). The hour is kept in memory, so it starts
  again when heimdalld restarts.
- It needs heimdalld's firewall watch: `"firewall"` not turned off in `/etc/heimdall/config.json`, and the `systemd-journal`
  group (`packaging/arch/heimdall-firewall.conf.example`). `status` says whether these alerts are reported.
- The alert names the device's address and hardware address. Both go into the kernel journal and `alerts.jsonl`, and to your
  other computers if the mesh is on.

## A second router (rogue DHCP and IPv6 router advertisements)

A device on the network can put itself between this computer and the internet without touching the router: by answering
the request for an address before the router does (a second DHCP server handing out itself as the router or DNS server), or
by announcing itself as the IPv6 router. heimdalld watches for both on every network, wired ones too, at every level:

| What | Alert |
|---|---|
| A DHCP server, router or DNS servers different from those of the first lease of this connection | warning |
| A device other than the first IPv6 router of this connection announcing itself as a router | warning |
| A new IPv6 prefix announced more than a minute after the router's first announcement | warning |
| An IPv6 router appearing more than 2 minutes after joining a network that had none | warning |
| On a trusted or home network: a DHCP server, router, DNS servers or IPv6 router other than the ones it remembers | critical |
| On a trusted or home network that never had IPv6 on 3 connections: an IPv6 router appearing | critical |

Each alert (`lan-watch`, event kind `rogue_router`) is one per connection for the same values and carries what was seen
before and after, so how often the checks fire can be measured later (see "Protective mode" below): `via` (`dhcp` or `ra`),
`signals` (which changed together, comma-separated: `dhcp_server`, `dhcp_router`, `dns4`, `dns6`, `ra_router`, `ra_prefix`,
`ipv6_new`, `ipv6_late`), `before` and `after` (`signal=value;...`; `remembered` where a trusted network keeps only a hash),
`learned` (whether it contradicts what a trusted network remembers), `confidence` (`high`: a trusted network's memory and two
or more signals agree; `medium`: one of the two; `low`: neither), `level`, `ssid`, `iface`. Nothing is blocked: everyone else
on the network can still use it. The alert says what was seen and what to do.

How it looks, without sending anything:
- **DHCP** from what NetworkManager accepted. The dispatcher `91-heimdall-netid` (root) writes one line per connection coming
  up or going and per lease change: the server's identifier, the router and DNS servers handed out, the IPv6 DNS servers, the
  interface and the profile's UUID (no network name), to `/run/heimdall-net/netid.jsonl` (root's folder, mode 0750, group
  heimdall; the file 0640, cut to its last 200 lines past 64 KiB; gone at reboot). A rogue server that answers this computer
  first, or later at a renewal, is seen; one whose offer NetworkManager never takes is not (that would need a listener on the
  network, which heimdalld does not have: it runs as its own user without the capability to open one).
- **IPv6** from the kernel's routing table (`/proc/net/ipv6_route`, every 10 seconds): the link-local next hops of the default
  routes are the routers that announced themselves, the on-link prefixes are what they announced. A router announcing a
  lifetime of 0 (withdrawing itself) is not reported, and changes to the IPv6 DNS servers between leases are not seen.

**What a trusted or home network remembers** is kept in `/var/lib/heimdall/wifi/routers.json` (heimdalld's own, mode 0600): per
network a hash of its UUID, and per signal hashes of the values seen (sha256 of the UUID, the signal and the value), the number
of connections and whether it has had IPv6. No address, name or hardware address is kept, and nothing at all for a network that
is not trusted (that would be a list of the places this computer has been). A new router is taken as the network's own once it
has been seen on 3 connections, so replacing the router gives a critical alert on each of the next 3 connections and then
stops. Only Wi-Fi networks have a level (from `heimdall-wifi-check`'s `current.json`); a wired connection is judged within the
connection only.

## Protective mode (planned, after training)

Not built. When Heimdall is confident that someone is in the middle, it should protect the connection rather than only warn,
while everyone, this computer included, stays on the network. Planned actions, each automatic only on a learned (trusted or
home) network at `high` confidence, each reversible, each with a notice and an "Undo":
- pin the known router's hardware address as a permanent neighbour entry (ARP spoofing then changes nothing for this computer);
- drop DHCP offers and IPv6 router advertisements that do not come from the known router (nftables, the Wi-Fi interface only);
- keep DNS on the resolvers the network is known to hand out;
- send everything through the VPN, if one is set up.

Never a full disconnect. The training gate comes first: per network an observe-only period that counts how often each check
fires on a network known to be clean (the `signals`, `confidence` and `before`/`after` fields above are recorded for this), and
no action is switched on until I approve a threshold from those numbers.

## What kind of network a trusted one is

A trusted or home network can be given a kind, my choice for it:

```
heimdall-wifi-guard kind [--uuid UUID]                 says it (no root needed)
sudo heimdall-wifi-guard kind KIND [--uuid UUID]       sets it: home-router, mesh, phone-hotspot, travel, other
```

It is stored as `"kind"` in the network's entry in `/etc/heimdall/wifi-trusted.json`; no `kind` (or `home-router`, which removes
it) means a home router, as before. `trust` and `trust --home` keep it; `untrust` removes the entry and the kind with it. A
network that is not trusted has no kind (`kind` refuses it). heimdalld judges a different router on the network by it:
- **home router:** its hardware address is the anchor;
- **phone hotspot:** a different router address after the hotspot restarts (a new connection) is expected. The anchors are the
  WPA2/WPA3-Personal handshake (a copy without the password cannot complete it), and the addresses and DNS servers it hands out;
- **mesh:** several router addresses of the same mesh are normal; the set learned is the anchor;
- **travel, other:** judged like a home router.

On every kind, the router's address changing during a connection, or two addresses answering as the router at once, stays a sign
of someone in the middle. Heimdall may suggest a kind but never sets it. **For Settings:** a list next to the trust level and the
discoverable switch on a Wi-Fi network's page, read with `heimdall-wifi-guard kind --uuid UUID` (`NAME: kind KIND`) and set with
`pkexec heimdall-wifi-guard kind KIND --uuid UUID` or a unit like the discoverable ones (not shipped yet).

## Discoverable: announcing on a network, whatever its level

Not announcing (no Avahi, discovery traffic held back) is the default on every network but home. A network can be made
**discoverable** on its own, independent of its trust level:

```
heimdall-wifi-guard discoverable [--uuid UUID]            says whether it is (no root needed)
sudo heimdall-wifi-guard discoverable on|off [--uuid UUID]   the network connected now, or the saved profile UUID
```

On a discoverable network this computer announces itself: Avahi runs as it did, and the quiet table is loaded with its outgoing
discovery drops left out (its comment then reads `heimdall quiet 3 discoverable`). Every other protection stays: the inbound
log and alerts, ufw, the VPN and its lockdown, the router watch, its own hardware address there and no computer name in its
address requests. On the network connected now it applies at once. Home is always discoverable.

The choice is stored in the network's entry in `/etc/heimdall/wifi-trusted.json` (`"discoverable": true`). A network that is not
trusted gets an entry of its own, `{"ssid": ..., "level": "untrusted", "discoverable": true}`, which counts as untrusted
everywhere (the guard, the check, the device list). `trust` and `untrust` keep the choice; `discoverable off` on such an entry
removes it. A profile renamed to another network, or a trusted profile found changed (its lock, its saved password), is not
discoverable. `status` lists it (", discoverable") and says "discoverable here: yes" for the network connected now. The check
then does not ask for "not announcing": a covered network is still "protected", and the notice says what this computer
announces there.

**For Yggdrasil Settings** (a switch on a Wi-Fi network's page), asking for an administrator's password (remembered for a few
minutes; the owner's choice):
- read: `heimdall-wifi-guard discoverable --uuid UUID` prints `NAME: discoverable on`, `on (home)` or `off`;
- change: start the unit `heimdall-wifi-discoverable-on@UUID.service` or `heimdall-wifi-discoverable-off@UUID.service`
  (systemd's D-Bus `org.freedesktop.systemd1.Manager.StartUnit(name, "replace")`, or `systemctl start NAME`). The units run
  `heimdall-wifi-guard discoverable on|off --uuid UUID` as root. Starting a unit is polkit's
  `org.freedesktop.systemd1.manage-units`, whose own default for an active local session is the administrator's password,
  remembered for a few minutes (`auth_admin_keep`): exactly what the owner asked for, so Heimdall ships no rule of its own for
  it. The guard takes only a UUID as NetworkManager writes it (8-4-4-4-12 lowercase hex digits) and refuses one that is not a
  saved Wi-Fi profile.

What being discoverable means beyond "this computer announces itself":
- On a network nobody needs a password for (open, or a discoverable untrusted network generally), this computer also announces
  itself to any copy of the network with the same name, since nothing tells the two apart.
- Devices answering what it announces (or what it asks, such as mDNS questions) send packets to this computer that the quiet
  table counts as starting something; on a busy network these can raise the hourly "a device tried to reach this computer"
  warning for those devices.

## The quiet table

On every network but home, the guard loads its own nftables table, `inet heimdall_wifi_quiet`, alongside ufw. It matches Wi-Fi
interfaces only (`wl*`), so a wired network, and the desktop, are never affected.

- **Output:** it drops this computer's discovery traffic on its way to the local network (multicast, broadcast, private and
  link-local addresses): NetBIOS (UDP 137, 138), KDE Connect (UDP and TCP 1714-1764), SSDP (UDP 1900), WS-Discovery (UDP
  3702), mDNS (UDP 5353), LLMNR (UDP and TCP 5355), Dropbox LAN sync (UDP 17500), Syncthing (UDP 21027) and Steam (UDP 27036).
  Traffic to an internet address on these ports is not touched (PPTP 1723 and H.323 1719/1720 share the KDE Connect range).
  The computer does not announce itself with these, whatever program tries and however quickly it does so after joining. A
  program announcing itself some other way is not covered. The cost is that on these networks this computer cannot discover
  casting targets, printers or the other devices of those programs itself, unless the network is made discoverable.
- **Input:** it only logs and accepts. It logs only a packet that starts something (`ct state new`, and for TCP a SYN without
  ACK), aimed at this computer (unicast, not broadcast or multicast), from a private or link-local address: once per sender an
  hour, with the prefix `heimdall-wifi-in:`, at most 30 a minute. The network's router (its IPv4 gateway, which the guard puts
  in the table's `router4` set on each connection) is logged once per connection instead, with the prefix
  `heimdall-wifi-in-router:`, and is an info alert, not a warning: routers that keep a list of their devices (a device map)
  look at each one regularly. A router on IPv6 only counts as a device. heimdalld reads only the kernel's lines with that prefix, for
  a Wi-Fi interface and a private or link-local sender. ufw's own chains still decide, and they drop anything not allowed: a
  packet has to pass every base chain.

The table is loaded in the synchronous `pre-up`, before the connection carries traffic. It stays in place when the network goes,
ready for the next one, and is removed only when a home network comes up. `sudo heimdall-wifi-guard quiet-check` prints the
table and checks it with `nft -c`. `status` (as root) shows how many discovery packets it held back. Avahi is still stopped
on these networks, and is started again only when no Wi-Fi is connected. The table was loaded in a throwaway network namespace
on a real kernel and sent packets: a SYN, a UDP packet and a ping from a private address were logged; a lone ACK, the answers of
a connection this computer made and packets from a public address were not; the discovery ports above were held back and DNS
was not.

## The verdict: protected

`heimdall-wifi-check` no longer counts the router or the phone hotspot itself as "another device". Its gateway address, and any
address carrying the gateway's hardware address, are left out. `results.jsonl` records how many devices were heard, never their
addresses, and is created mode 0640 (readable by heimdall only).

When other devices are heard, the network is not simply "needs care". If the guard has checked that the protections which
make being seen harmless are in force, the check is **covered**. Those protections are:
- ufw on, dropping incoming connections by default, and none of its own allow rules (`user.rules`, `user6.rules`) letting in a
  service that listens here beyond this computer (`ss`). They are read as ufw's backend reads them: a rule's comment
  (`comment=` in hex) comes off first, logged rules (`allow_log`, `limit_log`, `allow_log-all`) count, application rules
  ("OpenSSH") count, a rule with no direction is incoming, forwarded (`route:`) rules do not count. A rule that does is named in
  the caution and in `status`. `docs/MESH.md`'s own rule for the mesh port is one;
- the quiet table loaded, muting discovery, on this Wi-Fi interface (not asked on a network made discoverable);
- the computer's own hardware address in use.

A covered check gives the verdict **protected**, along with a plain list of what is still visible: that this computer is there
and answers pings (ufw's default rules answer them), the names of the sites you visit (DNS is not encrypted) and how much you
send. A VPN hides the last two. A protected network is one low-priority notification the first time, and an info alert in
Heimdall.

A protection that is not in force yet keeps the verdict at caution and names what is missing. On the first connection to a
network, for example, the private hardware address applies only from the next connection on.

The guard's `up` and the check both start when the connection comes up, and neither waits for the other. The guard's `pre-up`
marks the connection as coming up in its state, and the check waits for the guard's `up` to finish (at most 45 seconds) before
reading the protections. A mark older than two minutes is ignored. A late `down` of the previous connection leaves the next one
alone: its state, its lockdown and its VPN. When the guard finds the profile untrusted (its saved password changed), the check
records it as untrusted too.

## Time

The check may take `HEIMDALL_WIFI_CHECK_LIMIT` seconds (240 by default; its unit allows 300). Past half of that, no more secure
connections are asked of DNS answers ("could not confirm"). When the limit is reached, the check writes what it found so far,
with a warning "the check could not finish within N seconds", so a network that holds answers back cannot keep it from
reporting.

An Enhanced Open (OWE) network with the name of the one joined, nearby, is an evil twin: anyone can make one without the
password.

## DNS answers outside a site's own network

A well-known name that resolves outside its owner's network is not called spoofing on that ground alone, and no other company's
network is taken as the owner's. Heimdall opens one secure connection to each such address (at most 4 for each name), using the
name, and checks the certificate:
- a genuine certificate is "ok", because the answer leads to the real site;
- a certificate this computer does not trust is "bad: DNS spoofing";
- no answer is "caution: could not confirm", and so is an address beyond the 4 asked.

An answer that is a local address (private, link-local) must show the genuine certificate too; anything else is "bad". An
answer that points at this computer itself (127.0.0.0/8, 0.0.0.0/8) is "bad" without asking.

## Later

- "Trust this network" buttons on the notification, and a level selector in Settings.
- Loading the quiet table at boot, then no longer stopping Avahi at all.
- Devices that look up this computer, and new devices on trusted networks, without sending anything.
- IPv6 in the listener.
- A stronger router fingerprint per trusted network (the DHCP server and its options, router announcements, DNS servers, the
  router's hardware address, its admin certificate or SSH key if it already answers), judged by how many changed at once: one
  is "changed, maybe a firmware update", several "a different device may be posing as your router".
- A known device on a home network answering with another hardware address, name or maker (the device list's devices
  changing identity).
- Enterprise networks with a pinned certificate authority.
- Encrypted DNS.
- The status `not_home` in Settings' device list.
