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

On the **desktop** (wired): since 2026-11-18 its wired network is untrusted until I make it home, so it gets a hardware address
of its own, sends no computer name and uses IPv6 privacy addresses (below, "Wired networks"). If the router keeps an address
for it (a reservation, a port forward), run `sudo heimdall-wifi-guard trust --home --real-address` on it once. Nothing else
changes there: the lockdown, the VPN, the quiet table and the check act on Wi-Fi only. An entry in
`/etc/heimdall/wifi-trusted.json` from before the levels (no `level` key) is **home**, exactly as before.

On a **laptop**, even without a new command:
- the quiet table is loaded on every Wi-Fi network but home, and its profile gets `connection.llmnr no` and `connection.mdns no`;
- the "no VPN" notice still comes on every connection to an untrusted network, as before (the owner's choice); a trusted
  network never shows it;
- a home entry from before the levels whose router is a different one counts as trusted (it was untrusted). It keeps every
  protection and the VPN, and you get one notice a day instead of one per connection. The check's router warning stays as it
  was;
- DNS answers outside a site's own network are decided by the site's certificate (below);
- `results.jsonl` is made mode 0640 and records how many other devices were heard, not who.

## Wired networks

I decided on 2026-11-18 that untrusted wired networks get a random address by default, like Wi-Fi. A wired (Ethernet) network
is untrusted unless I make it home; there is no "trusted" level for it, because a wired network has no notices to stop
(`trust` alone on one stops with nothing changed and says so).

On an untrusted wired network the profile gets the same private settings as an untrusted Wi-Fi profile:
`ethernet.cloned-mac-address stable` (unless I chose an address in Settings), no computer name in DHCP, the DHCP client ID and
DHCPv6 DUID made from that address, and IPv6 privacy addresses (below). The guard writes them into the profile when the
connection comes up (they apply from the next connection), and `heimdall-wifi-privacy.conf` gives every wired profile that sets
none of its own the same from its first connection. Nothing else: no lockdown, no VPN, no quiet table, no Avahi change, and
`state.json` stays Wi-Fi's. While the real address is still in use (the profile said `permanent`, or NetworkManager had not
read the new defaults yet), the guard tells me once a day (event `wired`, "Wired: NAME"): from the next connection on, the
address is one of its own, and what to run at home.

```
sudo heimdall-wifi-guard trust --home                  make the wired network I am on home (the device list may look around)
sudo heimdall-wifi-guard trust --home --real-address   ... and use the real hardware address and computer name there
sudo heimdall-wifi-guard trust --home --uuid UUID      the wired one by its profile, when Wi-Fi is connected too
sudo heimdall-wifi-guard untrust NAME|UUID             back to untrusted: a private address and no name from the next connection
```

**A home wired network whose router keeps an address for this computer** (a DHCP reservation, a port forward, a device list
in the router's page) needs `trust --home --real-address`, exactly as a Wi-Fi home network does; without it the router sees
a new device. Reconnect afterwards (`nmcli connection up UUID`, or unplug and plug in).

Trust is by the profile's UUID, in the same file as Wi-Fi: `{"name": "Wired connection 1", "wired": true, "level": "home",
"trusted_at": ..., "routers": [...]}` (no `ssid`; `kind` is kept if set). A wired profile is not tied to one network:
NetworkManager uses "Wired connection 1" for whatever the cable is plugged into. So home is bound to the router's hardware
address (as a Wi-Fi home network is). On another router the guard puts the profile back to private (from the next
connection), and if it used the real address there it says so; back home, `trust --home --real-address` again. A router
that does not answer leaves the profile as it is.

What this does not cover:
- `stable` is per profile: the address is made from the profile's stable ID (its UUID unless set), so one wired profile shows
  the same made-up address on every network it joins. It hides the real address and its maker, but two networks can tell
  it is the same computer. A profile per place (or `random` in Settings, a new address each connection) avoids that.
- The first connection of a profile made before NetworkManager read the new defaults uses the real address (the notice says so).
- The device list (`heimdalld lan scan`) looks around a home wired network as on Wi-Fi; the router watch, the check and the
  inbound alerts stay Wi-Fi only (a wired connection is judged within the connection, "A second router" below).

## IPv6 privacy and DHCP identifiers

On every untrusted network, Wi-Fi and wired, the guard also sets `ipv6.ip6-privacy 2` (temporary addresses, RFC 8981, for
the connections this computer makes) and `ipv6.addr-gen-mode stable-privacy` (an interface ID that is not made from the
hardware address, RFC 7217, different on each network). They go in a `nmcli connection modify` of their own, so a profile
NetworkManager refuses them for (an IPv6 `token` needs `eui64`) keeps the other private settings. It also sets
`ipv4.dhcp-client-id mac` and `ipv6.dhcp-duid ll`: both made from the hardware address in use, the made-up one. Left alone,
NetworkManager's DHCPv6 DUID comes from the machine-id, the same on every network.

I chose both places, as for the hardware address: `heimdall-wifi-privacy.conf` sets them as NetworkManager's defaults (for
Wi-Fi and wired devices only, not bridges or VPNs) so a new profile has them from its first connection, and the guard writes
them into each untrusted profile so a profile that set weaker values of its own gets them too. Home keeps them; they cost
nothing there. Every made-up address is locally administered (the bit phones set); when the guard sets `stable` it also
clears `generate-mac-address-mask`, so no maker's prefix is kept or borrowed.

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
- **A device tried to reach this computer** (`lan-watch` info: listed, not notified), on every network but home. This covers a device on the
  network itself (a private or link-local address) starting a connection to this computer (a TCP SYN), sending it a new UDP
  packet (a direct question such as NetBIOS's "what is your name", unicast mDNS, LLMNR or SNMP) or pinging it. Packets of
  connections this computer made, late or stray packets, and anything from an internet address are never reported. Devices
  ask about others all the time, so each one is listed (an info alert: Settings shows it on the network's page under "Asked
  about this computer" and in Security under Everything) without a notification (my decision, 2026-11-22), once per device an
  hour and at most 30 devices an hour. A **warning** (a notification) comes only for what looks like a sweep: 6 different
  devices within 10 minutes (one device sweeping the network with made-up addresses, or someone scanning it), once an hour;
  one device trying many ports is the `inbound` check's port scan (10 ports in 10 minutes, from ufw's blocks). The hours are
  kept in memory, so they start again when heimdalld restarts.
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
| A new IPv6 prefix announced more than a minute after the router's first announcement | warning; none on a phone's USB link (below) |
| An IPv6 router appearing more than 2 minutes after joining a network that had none | warning |
| On a trusted or home network, at the start of a connection: **one** of its DHCP server, router, DNS servers, the router's hardware address or IPv6 router differs from what it remembers | info ("changed, maybe a firmware update") |
| ... **two or more** of them at once | critical ("a different device may be posing as your router") |
| On a trusted or home network: a DHCP server or IPv6 router it does not know appearing in the middle of a connection | critical |
| On a home network: the router's hardware address changing in the middle of a connection, whatever its kind (on every other network the router watch reports it) | critical |
| On a trusted or home network that never had IPv6 on 3 connections: an IPv6 router appearing | warning |

**A phone's USB link** (an iPhone's `ipheth`, an Android phone's `rndis_host`, read from the interface's driver in `/sys`):
only the phone is on that cable, and carriers change the IPv6 prefixes they hand out, so a new prefix there is noted in
heimdalld's log (`rogue-router: ... is a phone's USB link`) and is not an alert (my decision, 2026-11-22, after 19 warnings in
four minutes on an iPhone's link). Every other signal is watched there as everywhere, and a phone's Wi-Fi hotspot is watched
like any Wi-Fi network.

Each alert (`lan-watch`, event kind `rogue_router`) is one per connection for the same values and carries what was seen
before and after, so how often the checks fire can be counted per network: `via` (`dhcp` or `ra`),
`signals` (which changed together, comma-separated: `dhcp_server`, `dhcp_router`, `dns4`, `dns6`, `gateway_mac`, `ra_router`,
`ra_prefix`, `ipv6_new`, `ipv6_late`), `judged` (`info`, `warning` or `critical`, by the table above), `network_kind` (the
network's kind, below; empty on a network that is not trusted), `before` and `after` (`signal=value;...`; `remembered` where a trusted network keeps only a hash),
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
of connections and whether it has had IPv6. These hashes are the router's fingerprint: the DHCP server, the router and DNS servers it hands out, the router's hardware
address (from the kernel's neighbour table) and the IPv6 routers. No address, name or hardware address is kept, and nothing at all for a network that
is not trusted (that would be a list of the places this computer has been). A new router is taken as the network's own once it
has been seen on 3 connections, so replacing the router gives a critical alert on each of the next 3 connections and then
stops. Only Wi-Fi networks have a level (from `heimdall-wifi-check`'s `current.json`); a wired connection is judged within the
connection only.

## Protective mode

Not built: Heimdall warns when someone looks to be in the middle; it does not act on the connection itself (pinning the
router's address, dropping other routers' offers, keeping DNS, forcing the VPN).

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

In heimdalld today: on a phone hotspot the router's hardware address and its IPv6 router address at the start of a connection
are neither compared nor remembered; on a mesh, each address is learned like a new router (after 3 connections), so the set
of the mesh's addresses is the anchor; the other kinds remember every signal.

On every kind, the router's address changing during a connection, or two addresses answering as the router at once, stays a sign
of someone in the middle. Heimdall never sets a kind. **In Settings:** "This network is" next to the trust level
and the discoverable switch on a saved Wi-Fi network's page (Yggdrasil 2026-11-17), read with `heimdall-wifi-guard kind --uuid
UUID` (`NAME: kind KIND`) and set with `pkexec /usr/bin/heimdall-wifi-guard kind KIND --uuid UUID` (polkit's default: the
administrator's password); on an untrusted network it is shown off, "Trust this network first".

Heimdall does not suggest a kind; it is always my choice.

## Discoverable: announcing on a network, whatever its level

Not announcing (no Avahi, discovery traffic held back) is the default on every network but home. A network can be made
**discoverable** on its own, independent of its trust level:

```
heimdall-wifi-guard discoverable [--uuid UUID]            says whether it is (no root needed)
sudo heimdall-wifi-guard discoverable on|off [--uuid UUID]   the network connected now, or the saved profile UUID
```

On a discoverable network this computer announces itself: Avahi runs as it did, and the quiet table is loaded with its outgoing
discovery drops left out (its comment then reads `heimdall quiet 4 discoverable`). Every other protection stays: the inbound
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
  table counts as starting something; on a busy network these are listed as "a device tried to reach this computer" for
  those devices.

## The quiet table

On every network but home, the guard loads its own nftables table, `inet heimdall_wifi_quiet`, alongside ufw. It matches Wi-Fi
interfaces only (`wl*`), so a wired network, and the desktop, are never affected.

- **Output:** it drops this computer's discovery traffic on its way to the local network (multicast, broadcast, private and
  link-local addresses): NetBIOS (UDP 137, 138), KDE Connect (UDP and TCP 1714-1764), SSDP (UDP 1900), WS-Discovery (UDP
  3702), mDNS (UDP 5353), LLMNR (UDP and TCP 5355), Dropbox LAN sync (UDP 17500), Syncthing (UDP 21027), Steam (UDP 27036) and Spotify Connect (UDP 57621; Spotify also answers
  on mDNS and SSDP, held back above).
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

## Known limitations

- The Wi-Fi notification has no "Trust this network" button (Settings has the level selector).
- The quiet table is loaded when a connection comes up, not at boot, and Avahi is stopped on networks that are not home.
- Devices that look up this computer, and new devices on trusted networks that are not home, are not reported.
- The listener logs IPv4 only.
- The router's fingerprint does not include the DHCP option set (NetworkManager's dispatcher does not pass it), the router's
  admin certificate or SSH key, or the RA lifetimes.
- A known device on a home network announcing another device's name is not reported (a device taking another's address is:
  [DEVICES.md](DEVICES.md)).
- Enterprise (EAP) networks cannot be trusted.
- DNS is not encrypted.
