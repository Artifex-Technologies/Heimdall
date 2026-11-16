# Several internet connections at once

With more than one internet connection on at the same time (Wi-Fi and Ethernet, or either one and a phone over USB),
`heimdall-multilink` spreads this computer's new connections over all of them. Each connection stays on the link it started
on. Downloads that open many connections (a game store, a browser loading a page, a download manager, torrents) then use the
links' combined speed. It is off until I switch it on, in Settings > Wi-Fi & Network > Several connections at once, or with
`sudo heimdall-multilink on`.

The idea comes from [net-merge](https://github.com/net-merge/net-merge) (MIT), which spreads connections through a TUN
adapter. Nothing of its code is used. Here the kernel does the spreading with its own multipath routing, so no packet passes
through a program. It costs nothing per packet: the service only checks the links and looks after the routing.

## When it helps, and when it does not

- **The links must reach the internet by different ways**: two providers, or a provider and a phone's mobile data. Wi-Fi
  and Ethernet from the same router share that router's one internet line, so together they are no faster than either.
- **One connection is never faster.** A single download over one connection stays on one link. The gain comes from many
  connections at once.
- **Sites see more than one address.** Each link has its own public address, so a site that ties a login to an address
  (some banks, some shops) may ask me to log in again. Connections that are already open never move, so this happens only
  between connections.
- **With a VPN on there is nothing to spread**: everything goes through the VPN's one tunnel. The feature pauses while a VPN
  carries everything and says so. It starts again by itself once the VPN is off.
- **Mobile data costs money**: a phone link can get a share limit, a data cap per day or month, or be kept for backup only.

## How it works

The service reads the links from the main routing table. NetworkManager puts a default route there for every connection, and
the service never changes it. Next to it, the service keeps its own rules and tables, all tagged protocol 199:

| priority | rule | what it is for |
|---|---|---|
| 32000 | `lookup main suppress_prefixlength 0` | every route in the main table except the default one works as before: the local network, Limbo's bridges, Tailscale's addresses |
| 32001 | `to DNS iif lo fwmark 0 lookup LINK` | each link's DNS servers are asked over that link (a provider's server may answer only its own customers) |
| 32002 | `from ADDRESS fwmark 0 lookup LINK` | a connection that has a link's address stays on that link. Connections already open never move, each health check tests its own link, and replies pass the kernel's reverse path check |
| 32003 | `iif lo fwmark 0 lookup 7700000` | a new connection from a program on this computer takes the multipath default route |

Table 7700000 holds one default route with a nexthop per working link, weighted. Each link also has a table of its own
(7700000 plus its interface number) with only its default route. The kernel hashes each new connection's addresses and
ports (`fib_multipath_hash_policy=1`, for IPv4 and IPv6) to pick a nexthop. That decides the connection's source address,
and the source rule keeps the connection on that link from then on. While the service runs it also sets
`fib_multipath_use_neigh=1`, so the kernel skips a link whose router does not answer. It puts all three settings back when it
stops.

What is not spread: traffic this computer forwards (Limbo's guests, containers, anything with `iif` other than `lo`), and
any packet another program has marked (a VPN, Tailscale's own traffic). Those keep the routing they had.

### Living with NetworkManager

NetworkManager manages each connection: its address, its default route and its metric. The service changes none of it and
uses neither NetworkManager's profiles nor its multipath support (NetworkManager 1.58 can join static routes with a `weight`
into one multipath route, but only by changing the profiles. Every change of weight or health would then reconnect a
link). When NetworkManager reconnects a link, the kernel removes the routes through it, ours too. The service hears that
change on a netlink socket, looks again, and puts back what is missing within about a second.

### Off, stopped or crashed: back to normal

- `heimdall-multilink off` stops and disables the service.
- When it stops, the service removes every rule and route tagged 199, puts the sysctls back and removes its status file.
- systemd runs `heimdall-multilink restore` after every stop (`ExecStopPost`), including after a crash or a kill. That
  restore does the same cleanup, so a crash never leaves our routing behind.
- Without our rules, every lookup ends in the main table: NetworkManager's normal routing, which was never changed.
- systemd restarts a crashed service after 5 seconds. Until then the normal routing is in force. A service that stops
  answering is restarted by the watchdog after 30 seconds.

### Health checks and weights

Every 2 seconds each link opens a TCP connection through itself (bound to its device and its address) to `1.1.1.1:443` or
`9.9.9.9:443` (IPv6: `2606:4700:4700::1111`, `2620:fe::fe`), one after the other, and closes it as soon as it is made.
Nothing is sent but the handshake. A refused connection also counts as reached. These servers see each link's public address
then. Other servers can be set in `/etc/heimdall/multilink.json` (`probe4`, `probe6`: "IP:port" lists).

- After 3 failed checks in a row (about 6 seconds) a link drops out of the multipath route. New connections then avoid it.
  Connections already open on it break, as they would without this feature.
- After 2 good checks it comes back.
- Weights come from what each link has carried: the highest rate seen on it, forgotten slowly (half of it after about ten
  minutes). A new link counts as 1 MB/s, so links start with equal shares. Every link keeps at least 5 %, otherwise a link
  could never show it got faster.
- A link that answers much slower than the best one (more than twice as long, and 80 ms more) gets half its share.
- The route is changed only when a weight moves by 5 or more (out of 100).

### Each link's role

| role | what it means |
|---|---|
| **use** | new connections are spread over it (the default for a link seen for the first time; `heimdall-multilink new-links backup` changes that) |
| **backup only** | used only while no link set to use has internet |
| **off** | left alone: no rules of ours, no health checks |
| share limit | at most this percentage of new connections (1-99) |
| data cap | at most this many MB a day or a month, counting everything the interface sends and receives while the service runs; past it the link is kept for backup only until the next day or month (`/var/lib/heimdall-multilink/usage.json`) |

With fewer than two links set to use or backup, there is nothing to spread. The service then waits and changes nothing.

### DNS and the DNS block list

Name lookups go where they went before. Heimdall's DNS block list lives in NetworkManager's local DNS cache (dnsmasq at
`127.0.0.1`), which programs ask directly, so it still applies to every lookup. When the cache asks a link's own DNS server,
rule 32001 sends that question over the same link. With systemd-resolved, each link's DNS goes out of its own device as
before.

### Untrusted Wi-Fi and the Wi-Fi guard

The feature never changes the firewall, the quiet table, the private hardware address or anything else the Wi-Fi guard does
(docs/WIFI_TRUST.md), so an untrusted network keeps every protection. If the guard blocks a network until its VPN is up, the
health checks through that network fail and it stays out of the route. Once the VPN is up, the feature pauses. A network
should be marked trusted only for what `trust` means (fewer notices). Using it here changes nothing about that.

## Commands

```
heimdall-multilink status [--json]       what it does now (no password needed)
sudo heimdall-multilink on | off
sudo heimdall-multilink set LINK use|backup|off [--share PERCENT|none] [--cap MB|none] [--per day|month]
sudo heimdall-multilink new-links use|backup|off
```

Settings runs the same commands through `pkexec` (polkit action `org.heimdall.multilink`: an administrator's password,
remembered for a few minutes). Through pkexec the test options (`--config`, `--run-dir`, `--state-dir`) are refused.
`/run/heimdall-multilink/status.json` is what Settings shows. It exists only while the service runs.

The service runs as root with only `CAP_NET_ADMIN` (`packaging/multilink/heimdall-multilink.service`): the file system is
read-only to it except its own two folders and the three sysctls it sets, and it is limited to 64 MB of memory. It runs
`ip` (iproute2) for every change and `nmcli` to read each link's DNS servers and whether a NetworkManager VPN is on.

## A phone as the second link

My desktop has one Wi-Fi card, so it cannot be on my Wi-Fi and a phone's Wi-Fi hotspot at the same time. USB tethering gives
a second interface instead.

- **iPhone over USB**: the kernel's `ipheth` driver, plus `usbmuxd`, which pairs with the phone. `libimobiledevice`
  (`idevicepair`) is installed; `usbmuxd` is not yet (`sudo pacman -S usbmuxd`). Steps: unlock the phone, plug it in, tap
  **Trust** and enter the passcode, then turn on Settings > Personal Hotspot ("Allow Others to Join"). `idevicepair validate`
  says whether pairing worked. NetworkManager then brings up a new wired connection on an interface named like `enp0s20f0u1c4i2`.
  The phone answers at 172.20.10.1 by default.
- **Android over USB**: Settings > Network > Hotspot & tethering > USB tethering. The kernel's `rndis_host` or `cdc_ncm`
  driver does the rest; nothing more is needed.
- **Bluetooth (slow fallback)**: the phone's Bluetooth tethering, joined as a PAN network (`bnep`, BlueZ, and NetworkManager's
  Bluetooth support: `nmcli device connect` on the paired phone). Expect 1-2 Mbit/s.

A new phone link has the role in `new_links` (use, unless changed). For mobile data, set a cap:
`sudo heimdall-multilink set enp0s20f0u1c4i2 use --cap 2000 --per month`.

## Tests

- Unit tests (`cargo test -p heimdall-multilink --lib`): the config, the rules and routes worked out from the links, `ip`'s
  JSON read back, the weights, share limits, health, data caps.
- `tests/netns.rs` runs the real service in a made-up network inside a user, network and mount namespace of its own
  (`unshare -rnm`). Two links lead through two "providers" to an "internet" namespace, shaped with `tc tbf` to 40 and
  10 Mbit/s. It proves, in IPv4 and IPv6:
  - 60 connections to one server spread over both links;
  - the faster link gets the bigger weight (80 and 20);
  - a link whose provider loses its internet drops out in about 3 seconds and comes back;
  - backup only, a share limit and a data cap each work;
  - a VPN (a tun device with the two half-default routes) pauses it with nothing of ours left, and it resumes after;
  - stopping it leaves the rules, the main table and the sysctls exactly as before;
  - after a SIGKILL, `restore` cleans up;
  - with one link left it changes nothing.

  The test never touches this computer's real network. CI runs it on every push.
- In that test the service used about 0.1 % of one core while 40 Mbit/s of downloads went through it (a debug build,
  counting the `ip` commands it ran).
