# Devices on the home network

Heimdall keeps a list of the devices on each network you trust: what each one is, who made it, its name, when it first showed up and when it was last seen. Settings shows the list under **Wi-Fi & Network > Devices**. Each device that is new to the network raises a warning, because on a shared network you want to know who joins.

## When it looks

`heimdall-lan-scan.timer` runs `heimdalld lan scan` every 5 minutes, as the `heimdall` user, in its own sandboxed unit (heimdalld itself never touches the network). Settings' **Scan now** starts the same unit; a polkit rule (`50-heimdall-lan-scan.rules`) lets an administrator at the computer start that one unit without a password.

It only looks when all three of these hold:

- the connection carrying the default route is one you trusted (`heimdall-wifi-guard trust`, kept in `/etc/heimdall/wifi-trusted.json`);
- the router answers with the hardware address that was recorded when you trusted it (the same network name with another router is not your network);
- the subnet is no larger than /22 (1022 addresses).

Otherwise it records only why it did not look (`status` in the file: `not_trusted`, `router_changed`, `offline`). Looking around somebody else's network is not ours to do.

The first scan of a network learns what is already there without alerting. After that, every new hardware address is recorded in `events.jsonl` and becomes a `lan-watch` warning (event kind `new_lan_device`).

## How it finds devices

The scan only does what every phone and TV on a home network already does to find printers and speakers:

| Step | What it sends | What it learns |
| --- | --- | --- |
| Neighbour sweep | one 1-byte UDP datagram to port 9 ("discard") at each address, about 2000 a second at most | The kernel asks each address for its hardware address (ARP); every device that is on answers. The maker comes from the address's first half (IEEE list, `/usr/share/hwdata/oui.txt`). |
| Multicast DNS | the standard "which services are here?" question, then one question per service type | Names people gave their devices (Chromecast `fn`, Fire TV `n`, Matter `DN`, AirPlay, printers), models, services. |
| The router's names | a reverse DNS lookup of each address, asked of the router | The names devices gave the router when they joined ("iPhone-3"). |
| Windows names | a NetBIOS name query (UDP 137) to devices still unnamed | Windows and Samba computers' names. |

Addresses whose first byte has the "locally administered" bit set are private addresses (Wi-Fi privacy on phones, tablets and laptops): they name no maker, and the list says so.

What a device *is* (TV, speaker, printer, phone, computer, console, smart-home gadget) is a guess from its services, name and maker, shown as an icon.

### Why not SSDP (UPnP)

SSDP's answers come back unicast to a multicast question. The firewall cannot match those answers to the question, so it drops them, and Heimdall's inbound watch would then count every answer as a port tried. Multicast DNS answers go to the group, which the firewall's default rules accept.

This also explains a pattern in the inbound alerts: when a program on this computer (a browser looking for screens to cast to, a music app looking for speakers) asks the network who is there, the TVs that answer show up as "tried N different ports". Their answers are blocked; nothing connected.

## Files

| Path | What |
| --- | --- |
| `/var/lib/heimdall/lan/devices.json` | the list, per network (connection UUID and name), plus the last scan's status |
| `/var/lib/heimdall/lan/events.jsonl` | one line per new device; heimdalld follows it (`events.offset`) |

Both are readable only by the `heimdall` account. Settings reads the list through the local API (`GET /v1/lan/devices`, the same callers as every other endpoint). `heimdalld lan list` prints it on a terminal (as root or heimdall).

Configuration: `lan_dir` in `/etc/heimdall/config.json` (default `/var/lib/heimdall/lan`; empty turns the alert and the API route off).
