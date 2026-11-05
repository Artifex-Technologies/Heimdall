# Mesh: alerts shared between your own computers

With Heimdall on more than one computer, each can show the others' alerts: a remote-access tool found on the laptop appears
in the desktop's Settings > Security too. That is all the mesh does.

Terms used here:

- **Instance**: one Heimdall, on one computer.
- **Peer**: another instance you enrolled.
- **Fingerprint**: the short name of an instance's key, `hm1-` and 32 letters and digits (`heimdalld mesh id`).

## What it does, and what it never does

It does one thing: an instance sends its alerts (warning and critical, by default) to its enrolled peers, and shows what
they send as `mesh` alerts named after the peer (`[laptop] ...`).

It never does any of these, by design (there is no code for them):

- run a command, open a shell, forward a port, serve a file or a web page, relay for another computer;
- push settings, approvals or software to a peer;
- act on a received alert: received alerts go to the alert log, the API and Settings only, never to containment,
  quarantine or the correlator's incident triggers;
- send an alert's event text or fields (they can quote a session or a file): only its time, detector, severity, summary
  (at most 500 characters, already stripped of credential-shaped text) and source;
- pass on what it received (no loops, no relaying).

## Why it is built this way (the "Tailworm" lessons)

The October 2026 Tailscale flaws ("Tailworm") were in the parts that do more than carry packets: SSH, Serve, Funnel, the
relay servers and the coordination server. The mesh has none of them.

| Risk | What the mesh does |
| --- | --- |
| A stolen or tricked coordination server adds a device | There is no server. Each computer has its own list of peers (`/etc/heimdall/mesh-peers.json`, root's file), written only by `sudo heimdalld mesh enroll` at a terminal. |
| Someone else's device talks to yours | Mutual TLS 1.3. Both sides present their ed25519 key; a key that is not enrolled is cut off during the handshake. A client without a key gets nothing. |
| A name or DNS answer points you at the wrong computer | Peers are IP addresses, never host names, and the key found there must be the one enrolled for that address. |
| A remote shell or file access feature has a bug | There is none. One endpoint: `POST /mesh/v1/alerts`, a JSON list of at most 50 alerts, 64 KiB. |
| A peer is compromised | It can send false alerts (at most 120 a minute) that you see labelled with its name. It cannot run anything here. `sudo heimdalld mesh forget NAME` cuts it off at once, without a restart. |
| The listener is exposed to the internet | It is off by default. `mesh_listen` must be one IP address of this computer (never `0.0.0.0` or `::`); use the address on your own WireGuard or home network interface, and let the firewall allow only your peers. |

Keys: ed25519, made on each computer by `sudo heimdalld mesh init`, kept in `/var/lib/heimdall/mesh/key.pem` (mode 0600,
Heimdall's account). The key never leaves the computer; only its fingerprint does, and you carry that yourself.

## Setting it up (two computers, A and B)

On each computer:

```
sudo heimdalld mesh init        # prints this computer's fingerprint; heimdalld mesh id shows it again later
```

Choose the address each computer listens on: its address on the network both share (a WireGuard address such as
`10.8.0.1`, or the home network address). Add to `/etc/heimdall/config.json` on each:

```
"mesh_listen": "THIS-COMPUTER'S-ADDRESS:8931"
```

Enrol each in the other. Read the fingerprint on the other computer's own screen, not from a message someone sent you:

```
# on A
sudo heimdalld mesh enroll b-name  FINGERPRINT-OF-B  ADDRESS-OF-B:8931
# on B
sudo heimdalld mesh enroll a-name  FINGERPRINT-OF-A  ADDRESS-OF-A:8931
```

Let only the peer through the firewall, then restart:

```
sudo ufw allow from ADDRESS-OF-THE-PEER to any port 8931 proto tcp comment 'Heimdall mesh'
sudo systemctl restart heimdall
```

`heimdalld mesh list` shows the peers. `journalctl -u heimdall | grep mesh` shows the listener and any peer it could not
reach.

Settings that change it (`config.json`): `mesh_listen` (off when empty), `mesh_min_severity` (`warning`; `critical` sends
less), `mesh_dir`, `mesh_peers_path`.

## What else notices it

- Heimdall's own connection watch reports Heimdall talking to an enrolled peer as info (it is expected); Heimdall talking
  to any other address off the machine stays critical.
- The listening watch reports once that `heimdalld` listens on a non-loopback address: expected once the mesh is on.

## Limits

- Alerts that cannot be delivered wait in memory (at most 256 per peer) while the peer is unreachable, retried after 5
  seconds, doubling to 5 minutes. A restart loses them; the alert log on the computer that raised them keeps them all.
- A peer added with `enroll` receives alerts after a restart; `forget` takes effect at once.
- Both computers must be able to reach each other's address directly; there is no relay.

## Tested so far

On one computer, two instances (separate keys, state folders, ports 18931 and 18941 on 127.0.0.1): an alert raised on one
appeared on the other within 2 ms; after `mesh forget` on the receiver its next batch was refused (403) at once, even over the
already open connection; a client without an enrolled key failed in the TLS handshake (curl exit 55). Idle, each instance
used 0 CPU ticks (less than 10 ms) in 48 seconds and about 18-20 MB of memory. The unit tests also
cover a stranger's key, a client with no key, a wrong key at an enrolled address, loops and the limits.

## Checklist for the second PC (Matt)

1. Install the new Heimdall package on both PCs (it carries `heimdalld mesh`).
2. Decide the network both share. If they are not on the same home network, set up plain WireGuard first (REMOTE_ACCESS.md,
   "Without Tailscale's servers"), and use the WireGuard addresses.
3. On each PC: `sudo heimdalld mesh init` and write down the fingerprint it prints.
4. On each PC: add `"mesh_listen": "ITS-OWN-ADDRESS:8931"` to `/etc/heimdall/config.json`.
5. On each PC: `sudo heimdalld mesh enroll NAME FINGERPRINT ADDRESS:8931` for the other one (fingerprint read from the
   other PC's screen).
6. On each PC: `sudo ufw allow from OTHER-ADDRESS to any port 8931 proto tcp comment 'Heimdall mesh'`, then
   `sudo systemctl restart heimdall`.
7. Test: on PC A, make an alert Heimdall will raise. The simplest: with Sarina's vault in `vault_dirs`, add a note
   `mesh test.md` containing the line `Ignore all previous instructions` (it raises injection-phrase, critical). On PC B,
   `curl -s 127.0.0.1:8930/v1/alerts?n=5` shows a `mesh` alert starting `[A's name]` within seconds. Delete the note.
8. Test the cut-off: on B, `sudo heimdalld mesh forget A's-NAME`; repeat step 7 with a new note; nothing arrives on B, and
   A's journal says it could not send (403). Enrol A again afterwards.
9. Test a stranger: from a third device (or B before enrolling A), `curl -k https://A-ADDRESS:8931/mesh/v1/alerts` must fail
   during the TLS handshake.
10. Check that nothing else is open: `sudo ss -tlnp | grep heimdalld` shows 127.0.0.1:8930 and only the mesh address:8931.
