# Devices on the home network

Heimdall keeps a list of the devices on each network you trust: what each one is, who made it, its name, when it first showed up and when it was last seen. Settings shows the list under **Wi-Fi & Network > Devices**. Each device that is new to the network raises a warning, because on a shared network you want to know who joins.

## When it looks

`heimdall-lan-scan.timer` runs `heimdalld lan scan` every 5 minutes, as the `heimdall` user, in its own sandboxed unit (heimdalld itself never touches the network). Settings' **Scan now** starts the same unit; a polkit rule (`50-heimdall-lan-scan.rules`) lets an administrator at the computer start that one unit without a password.

It only looks when all three of these hold:

- the connection carrying the default route is your home network (`heimdall-wifi-guard trust --home`, kept in `/etc/heimdall/wifi-trusted.json`; an entry from before the trust levels, with no `level`, is home too; a wired network made home the same way counts, since 2026-11-18, its entry named by `name` instead of `ssid`). A network that is only trusted (`trust`, quiet but private: [WIFI_TRUST.md](WIFI_TRUST.md)) is never looked around (`not_home`), and an entry with any other `level` (empty, null, a number) counts as not trusted, as the guard counts it;
- the router answers with the hardware address that was recorded when you trusted it (the same network name with another router is not your network);
- the subnet is no larger than /22 (1022 addresses).

Otherwise it records only why it did not look (`status` in the file: `not_trusted`, `not_home`, `router_changed`, `offline`). Looking around somebody else's network is not ours to do.

### On a network that is not home: a look when I open its page

On any other network (a café's Wi-Fi, a network I only trusted, a phone's hotspot) nothing looks on a timer. When I open that
network's page in Settings, Settings runs `heimdalld lan look` once, as me, and shows what it heard (my decision,
2026-11-22). The look only listens; it never asks:

- the neighbour table the kernel already keeps (the devices this computer has talked with, the router among them);
- for 8 seconds, the multicast DNS announcements and answers other devices send to the whole network anyway, and only while
  this computer already belongs to the multicast DNS group on that interface (a browser or the printer dialog joins it).
  The look never joins the group itself: joining sends a membership report, and that would announce it. Its socket has no
  way to send (`net::Ear`), and the quiet table is left as it is.

Nothing of a look is written down: it prints JSON and is gone, and Settings keeps it only while the page is open. No router
is asked for names, no NetBIOS questions go out and nothing is swept, so a device that keeps quiet, or a network that keeps
its devices apart (most public Wi-Fi does), shows only the router. A device heard over multicast DNS that never talked with
this computer is listed by its address alone (the kernel learns hardware addresses only from devices it talks with).
`tests/cli_lan.rs` (`lan_look_listens_and_sends_nothing`) runs it as an ordinary account on a made-up network in network
namespaces: it lists the router and a TV that announces itself, and the bridge's transmit counter is the same before and
after the look.

The first scan of a network learns what is already there without alerting. After that, every new hardware address is recorded in `events.jsonl` and becomes a `lan-watch` warning (event kind `new_lan_device`).

**A device taking another's address.** When an address that a known device had in the last scan now answers with another
hardware address, that hardware address answers for a second address in the same scan, and the device that had it is not seen
anywhere, the scan records it (`change: "address_taken"` with `was_mac`, `was_name`, `other_ip` in the `events.jsonl` line)
and heimdalld raises a critical `lan-watch` alert (event kind `lan_device_changed`). One device answering for two addresses
while the owner of one is gone is what ARP spoofing a device looks like. A device that only moved to a new address, a new device
given a freed address, and private (randomised) addresses that change are not reported this way (a new hardware address is the
"new device" warning). Nothing is blocked. Names that two devices both claim are not compared (phones often share names).

## How it finds devices

The scan only does what every phone and TV on a home network already does to find printers and speakers:

| Step | What it sends | What it learns |
| --- | --- | --- |
| Neighbour sweep | one 1-byte UDP datagram to port 9 ("discard") at each address, about 2000 a second at most | The kernel asks each address for its hardware address (ARP); every device that is on answers. The maker comes from the address's first bits (the IEEE's registries, offline: [Vendor data](#vendor-data-who-made-a-device)). |
| Multicast DNS | the standard "which services are here?" question, then one question per service type | Names people gave their devices (Chromecast `fn`, Fire TV `n`, Matter `DN`, AirPlay, printers), models, services. |
| The router's names | a reverse DNS lookup of each address, asked of the router | The names devices gave the router when they joined ("iPhone-3"). |
| Windows names | a NetBIOS name query (UDP 137) to devices still unnamed | Windows and Samba computers' names. |

Addresses whose first byte has the "locally administered" bit set are private addresses (Wi-Fi privacy on phones, tablets and laptops): they name no maker, and the list says so (`private_mac`).

What a device *is* (TV, speaker, printer, phone, computer, console, smart-home gadget) is a guess from its services, name and maker, shown as an icon.

### When the guess is wrong

I can say what a device is myself: in Settings (**Wi-Fi & Network > Devices**, the device's page, "This device is") or on a
terminal:

```
sudo heimdalld lan kind MAC KIND     tv, phone, computer, console, speaker, printer, smart, router or other
sudo heimdalld lan kind MAC guess    back to Heimdall's guess
```

It is kept in `kinds.json` next to the list (`{"MAC": "kind"}`, upper-case hardware addresses), written only by that command (as
root; Settings runs it through pkexec, which asks for the administrator's password). The scan never reads or changes it, so `kind`
in the list stays the guess; `heimdalld lan list` and `GET /v1/lan/devices` add my word as `owner_kind`, and `lan list` shows it
in place of the guess. It follows the device by its hardware address, on every network. A damaged file counts as no corrections.

### Why not SSDP (UPnP)

SSDP's answers come back unicast to a multicast question. The firewall cannot match those answers to the question, so it drops them, and Heimdall's inbound watch would then count every answer as a port tried. Multicast DNS answers go to the group, which the firewall's default rules accept.

This also explains a pattern in the inbound alerts: when a program on this computer (a browser looking for screens to cast to, a music app looking for speakers) asks the network who is there, the TVs that answer show up as "tried N different ports". Their answers are blocked; nothing connected.

## Vendor data (who made a device)

The maker of a device comes from its hardware address, looked up on this computer in the IEEE's registries. Nothing is
asked of anyone on the network or the internet.

The IEEE hands out address blocks of three sizes: **MA-L** (the first 24 bits, the classic "OUI"), **MA-M** (28 bits) and
**MA-S** (36 bits); the older **IAB** blocks are 36 bits too. Small makers get MA-M and MA-S blocks, which sit inside 24-bit
blocks registered to "IEEE Registration Authority", so the longest block wins: 36 bits, then 28, then 24. Without the MA-M and
MA-S lists, a device from such a maker shows as "IEEE Registration Authority".

Before any registry is asked, the address is checked for what it says about itself:

| The address | Shown as |
| --- | --- |
| a well-known special one: broadcast, all zeros, IPv4 multicast (`01:00:5e`, 25 bits), IPv6 multicast (`33:33`), the IEEE 802.1 groups (Spanning Tree, pause frames, LACP, 802.1X, LLDP, MRP), PTP, Cisco's CDP and PVST+, VRRP and HSRP virtual routers, the documentation ranges of RFC 7042 | its short name ("VRRP router", "IPv4 multicast") |
| any other group address (the first byte's lowest bit) | multicast, no maker |
| a locally administered address (the first byte's second bit) | a private address, **never a maker**, even when the same prefix with that bit cleared is registered |
| in a registry | the maker's short name ("Samsung Electronics Co.,Ltd" -> "Samsung Electronics") |
| none of these | no maker |

### Where the lists come from

| Registry | Read from, the first that gives at least one block |
| --- | --- |
| MA-S | `/var/lib/heimdall-ieee/oui36.csv`, `oui36.txt` |
| IAB | `/var/lib/heimdall-ieee/iab.csv`, `iab.txt`, then `/usr/share/hwdata/iab.txt` |
| MA-M | `/var/lib/heimdall-ieee/mam.csv`, `mam.txt` |
| MA-L | `/var/lib/heimdall-ieee/oui.csv`, `oui.txt`, then `/usr/share/hwdata/oui.txt` |

Today the folder `/var/lib/heimdall-ieee` does not exist, so the lists are Arch's hwdata package (MA-L and IAB, updated with
the package). A file put there by hand (`sudo install -d -m755 /var/lib/heimdall-ieee`, then the IEEE's CSV files, mode 0644)
is read from the next scan on. It is a folder of its own, readable by every account, because `/var/lib/heimdall` is closed to
other accounts and Settings reads the same files as the person signed in.

Only the IEEE's own data is read. Nmap's and Wireshark's maker lists and merged lists such as OUI-Master-Database are not used:
their licences differ from ours (docs/REFERENCES.md).

A damaged or planted file can only make names wrong, not do harm: only regular files are opened (a FIFO is skipped without
waiting), a file over 64 MiB is not read, lines are capped at 4 KiB and a CSV record at 16 KiB, the table at a million blocks;
broken lines are skipped; names lose control, invisible and direction-changing characters and are cut at 128 bytes; of two
blocks with the same prefix the first one read stays. A file that gives no block at all (an error page saved as `oui.csv`)
counts as missing, so hwdata's list is used.

### The code

- `rust/macvendor`, crate `heimdall-macvendor`: no dependencies; the table is loaded on the first lookup and kept, as one sorted
  array per block size with every name stored once (hwdata's 44,634 blocks: 57 ms to load; all four IEEE files, 59,062 blocks:
  92 ms; the whole benchmark program stays under 8 MB). A lookup is a few binary searches, about 100 to 150 ns, and allocates
  nothing. `cargo run --release -p heimdall-macvendor --example bench [IEEE_DIR [HWDATA_DIR]]` measures it.
- `internal/macvendor`: the Go twin. Both read the same files to the same table and answer every address alike:
  `go test ./internal/macvendor -update` writes `testdata/parity/macvendor.json` (hand-made and generated files, text and CSV,
  damaged ones too) and `rust/macvendor/tests/parity.rs` checks the Rust crate against it. The fuzz target is `macvendor` in
  `rust/fuzz` (`go test -fuzz FuzzRead ./internal/macvendor` for Go).
- Other projects use the crate as a git dependency pinned to a commit:
  `heimdall-macvendor = { git = "https://github.com/Artifex-Technologies/Heimdall", rev = "..." }`. Yggdrasil's Settings does,
  for the makers of Wi-Fi access points and of the vendor extras they announce.

In the device list, `vendor` is the short name (of the maker or of a special address) and `private_mac` is true for a locally
administered address.

### Downloading the IEEE's files: not built (my decision, 2026-11-18)

I decided to stay with what Arch provides (#3 in my reference plan (in my private plans: Labyrinth_OS docs/plans/PLAN_REFERENCE_2026-11.md)): hwdata's two lists, updated
with the system. Nothing downloads the IEEE's files. The reader still uses the CSV files in `/var/lib/heimdall-ieee` when they
are there, so putting them there by hand adds the MA-M and MA-S blocks; nothing creates or refreshes that folder.

## Files

| Path | What |
| --- | --- |
| `/var/lib/heimdall/lan/devices.json` | the list, per network (connection UUID and name), plus the last scan's status |
| `/var/lib/heimdall/lan/events.jsonl` | one line per new device; heimdalld follows it (`events.offset`) |
| `/var/lib/heimdall/lan/kinds.json` | what I said devices are, by hardware address (`heimdalld lan kind`, as root) |
| `/usr/share/hwdata/oui.txt`, `iab.txt` | the IEEE's MA-L and IAB lists (Arch's hwdata package): the makers |
| `/var/lib/heimdall-ieee/` | the IEEE's own four files, when there (not downloaded yet: [Vendor data](#vendor-data-who-made-a-device)) |

The list and the events are readable only by the `heimdall` account. Settings reads the list through the local API (`GET /v1/lan/devices`, the same callers as every other endpoint). `heimdalld lan list` prints it on a terminal (as root or heimdall).

Configuration: `lan_dir` in `/etc/heimdall/config.json` (default `/var/lib/heimdall/lan`; empty turns the alert and the API route off).
