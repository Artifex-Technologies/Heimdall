# Why is the Wi-Fi slow?

`heimdalld wifi-health` (and **Settings > Wi-Fi & Network > Wi-Fi checks**) measures the connection for about ten seconds
and names the likely cause: a weak signal, a crowded channel, other devices using the network, the link to the router, or a
problem past the router (the internet provider). Nothing is changed. Any user may run it.

```
heimdalld wifi-health            # the report in words
heimdalld wifi-health --speed    # plus a download test (about 10 seconds more)
heimdalld wifi-health --json     # for Settings
```

## What it looks at

| Check | Source | Judged |
| --- | --- | --- |
| Signal | `iw dev IF link` | -60 dBm and better strong, to -67 good, to -75 fair (warning), below weak |
| Band | NetworkManager's scan list | on 2.4 GHz while the same network is offered on 5 GHz: warning |
| Channel | scan list | other networks on an overlapping channel heard above 40 % (about -80 dBm): 2.4 GHz 3+ warning, 6+ bad; 5 GHz 2+ warning, 4+ bad. Quieter channels are suggested (1/6/11; 36, 149, 52, 100, 116, 132). Networks the router itself sends (an internet provider's hotspot on the same radio: hardware address differing only in the first or last byte) are named, not counted. |
| Resending | `iw dev IF station dump` counters, before and after | share of frames sent again during the check (since connecting, if too little was sent): 10 % warning, 25 % bad |
| Router | 30 pings, 0.25 s apart | judged on the **median** answer and loss: median 15 ms or 2 % loss warning, 40 ms or 5 % bad |
| Power saving | `iw dev IF get power_save` | when on and a few answers are very late (power saving naps between beacons), said so as information, not blamed |
| Internet | 30 pings to 1.1.1.1 | median 60 ms or 2 % loss warning, 100 ms or 5 % bad; "past the router" when the router link is fine |
| Other devices | Heimdall's device list (`docs/DEVICES.md`) | good signal, quiet channel, little resending, yet the router answers slowly: other devices are using the Wi-Fi heavily |
| Speed (`--speed`) | two downloads for 8 seconds from the first https mirrors in `/etc/pacman.d/mirrorlist` (the installer image, read in part) | under 10 Mbps warning; answers 100 ms slower while downloading: "slow answers while the line is full" (bufferbloat) |

The speed test uses the Arch mirror the computer already updates from: public speed test sites turn programs away, and M-Lab
publishes each tester's address. Mirrors take no uploads, so upload speed is not measured. A busy mirror can make the line
look slower than it is.

Needs `iw` (a dependency of the package). Intel adapters do not report how busy the channel is (`iw survey dump` is empty),
so crowding comes from the scan list and the resending counters.
