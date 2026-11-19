# Shadow mode: the Rust daemon beside the Go one for a week

`heimdalld-rs run --shadow` reads the real sources and writes its own alert log; it takes **no responses** (no Limbo hold,
no containment request, no copy of a held file, nothing to a mesh peer) and serves no API. The Go `heimdall.service` stays
as it is and stays in charge. After a week, `shadow-compare.py` compares the two alert logs. Plan and proofs so far:
`docs/RUST_PORT.md`.

What the shadow daemon watches: Sarina's sessions and vault notes (inotify), Limbo's event log, the FIM list
(`fim_paths`), host telemetry, the maintenance window, the /proc/net watchers (ecosystem ports, connections with the IP
databases and threat lists, new listeners), the journal (firewall blocks, SSH logins; one `journalctl --follow`), the
Wi-Fi results and router watch, the trusted network's device events and remote-access tools (packages, tunnels, programs),
the 6-hourly package, kernel and hardening audits (on a thread of their own, waiting while a game runs; since 2026-11-10),
through every detector, the verifier, the explanations, the tool rules, maintenance softening and the correlator's incidents
(since 2026-11-10). **Not yet** (logged at start): trust. The audits run at each daemon's own start and then every 6 hours,
so the comparison counts their alerts within 7 hours of either end of the window as edge alerts (`--audit-edge-hours`).

The journal needs the `systemd-journal` group, as the Go daemon has it from its firewall drop-in: copy that drop-in too
(step 4 below copies every drop-in of `heimdall.service`).

The Wi-Fi results and the device list are read from where the Go daemon reads them; their offsets (which the Go daemon keeps
next to them, in its own read-only folder) the shadow daemon keeps beside its alert log (`wifi-results.offset`,
`lan-events.offset`), starting from the Go daemon's offsets the first time. A problem that stays is logged once an hour, not
on every look. (Fixed 2026-11-10: the first build tried to write the offsets next to the results and logged "read-only file
system" every few seconds.)

Safety: the unit runs as `heimdall` with no IP traffic at all (`IPAddressDeny=any`, only Unix sockets), writes only `/var/lib/heimdall-rs`, and
`/var/lib/heimdall` is read-only to it; `heimdalld-rs` itself also refuses a config with any state or log path in
`/var/lib/heimdall/`. Stopping it changes nothing for the Go daemon.

## Steps (run them yourself; nothing here was installed by the session)

```bash
cd ~/Documents/Github/Heimdall
git pull

# 1. build (at nice 15) and install the binary beside the Go one
cd rust && scripts/nicecargo.sh build --release --locked && cd ..
sudo install -Dm755 rust/target/release/heimdalld-rs /usr/local/bin/heimdalld-rs
heimdalld-rs rules check                          # "the built-in rules: 28 rules, all checked"

# 2. its config: the Go config with every written path moved to /var/lib/heimdall-rs/, the API off
python3 -I rust/parity/shadow-config.py /etc/heimdall/config.json > /tmp/shadow-config.json
grep -n '/var/lib/heimdall/' /tmp/shadow-config.json  # only paths it reads (pacman, IP databases, intel) may remain
sudo install -Dm640 -o root -g heimdall /tmp/shadow-config.json /etc/heimdall/shadow-config.json

# 3. its state: a copy of the Go daemon's positions, so it starts where the Go daemon is (no flood of old sessions)
sudo install -d -o heimdall -g heimdall -m 0750 /var/lib/heimdall-rs
for f in agent-sessions.json vault-notes.json agent-baseline.json fim.json limbo-offset package-audit.json kernel-audit.json hardening.json connections-state.json; do
  sudo test -e /var/lib/heimdall/$f && sudo install -o heimdall -g heimdall -m 0600 /var/lib/heimdall/$f /var/lib/heimdall-rs/$f
done
# (fim.json and limbo-offset: only if /etc/heimdall/config.json names them there; check fim_state_path, limbo_state_path)
# (connections-state.json: the destinations the Go daemon has learned; added 2026-11-18, see "Reading the connection log")

# 4. the unit, with the same read access as the Go daemon (its drop-ins: Limbo's group, the connection read rights)
sudo install -Dm644 packaging/arch/heimdall-shadow.service /etc/systemd/system/heimdall-shadow.service
sudo mkdir -p /etc/systemd/system/heimdall-shadow.service.d
sudo cp /etc/systemd/system/heimdall.service.d/*.conf /etc/systemd/system/heimdall-shadow.service.d/ 2>/dev/null || true
sudo cp /usr/lib/systemd/system/heimdall.service.d/*.conf /etc/systemd/system/heimdall-shadow.service.d/ 2>/dev/null || true
sudo systemctl daemon-reload
sudo systemctl start heimdall-shadow
date -u +%Y-%m-%dT%H:%M:%SZ > ~/heimdall-shadow-start.txt   # the comparison's start
```

## Updating the binary during the week

The shadow daemon keeps its state across a restart, so a newer build can replace it at any time. One update matters
(2026-11-10): from then on the shadow daemon also judges the AI agents' behaviour files against the signed list (trust), as
the Go daemon does. A binary built before that raises no trust findings, so with trust on (`heimdalld trust status` says
`watch` or `enforce`) a change to a behaviour file would show as a difference. With trust `off` nothing changes.

```bash
cd ~/Documents/Github/Heimdall && git pull
cd rust && scripts/nicecargo.sh build --release --locked && cd ..
sudo install -Dm755 rust/target/release/heimdalld-rs /usr/local/bin/heimdalld-rs
sudo systemctl restart heimdall-shadow
journalctl -u heimdall-shadow -n 30 --no-pager      # with trust on: "trust watch: watching N behaviour file(s) ..."
```

## Check that it runs

```bash
systemctl status heimdall-shadow --no-pager
journalctl -u heimdall-shadow -n 30 --no-pager      # "shadow mode: ...", the sources it watches, the ones not ported yet
systemctl show heimdall-shadow -p CPUWeight -p IOWeight -p Nice   # 20, 20, 10
pid=$(systemctl show -p MainPID --value heimdall-shadow)
grep -E '^(VmRSS|Threads)' /proc/$pid/status; sudo grep -E '^Pss:' /proc/$pid/smaps_rollup
gopid=$(systemctl show -p MainPID --value heimdall)
grep -E '^(VmRSS|Threads)' /proc/$gopid/status; sudo grep -E '^Pss:' /proc/$gopid/smaps_rollup
```

CPU over a day, both daemons (clock ticks of user + system time; divide the difference by the seconds between two readings
and by `getconf CLK_TCK` for "share of a core"):

```bash
for p in $pid $gopid; do awk '{print $14+$15}' /proc/$p/stat; done; date +%s
```

## After a week: compare

```bash
sudo cp /var/lib/heimdall/alerts.jsonl /tmp/go-alerts.jsonl          # alert_log_path of the Go config, if it is there
sudo cp /var/lib/heimdall-rs/alerts.jsonl /tmp/rs-alerts.jsonl
sudo chown "$USER" /tmp/go-alerts.jsonl /tmp/rs-alerts.jsonl
python3 -I rust/parity/shadow-compare.py /tmp/go-alerts.jsonl /tmp/rs-alerts.jsonl \
    --since "$(cat ~/heimdall-shadow-start.txt)" --until "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

"NO DIFFERENCE in the compared detectors" is the result wanted. Any difference it prints is a bug in the port to fix
before the switch (the alert lines are real data: keep them private, do not paste them into an issue), unless it is one of
the causes below that are not the port's. The tool prints how many alerts differ on each side and for which detectors, then
the first 40 lines of each side: read the counts, not only the lines (the first week's 40 and 40 lines were all
connection-watch, sorted first, and hid ten differences of other detectors). Put the CPU and memory readings and the
comparison's summary lines in the progress log (in my private plans: docs/plans/progress.md).

Causes that are not the port's (check each before calling a difference a bug):

- **The Go config changed during the week.** The shadow config is a copy made at step 2; a path added to the Go config later
  (a new `fim_paths` entry) is watched only by the Go daemon. Compare the two (`sudo diff <(python3 -I
  rust/parity/shadow-config.py /etc/heimdall/config.json) /etc/heimdall/shadow-config.json`, only the moved paths and
  `api_addr` may differ), and run step 2 again (then restart the shadow daemon) whenever the Go config changes.
- **A check newer than the shadow binary.** The Go daemon is the package from a recent main; a detector or audit check added
  after the shadow binary was built is Go's only. `heimdalld-rs version` and the date of the commit that added it tell.
- **One daemon was not running.** A listener that started while the shadow daemon was stopped is part of what it finds
  already listening when it starts, which it records without an alert, as the Go daemon does on its own start
  (`journalctl -u heimdall-shadow` shows when it started).

### The result (2026-11-19)

One clean day on my PC (2026-11-18 15:55 UTC to a reboot at 06:11 UTC the next day), compared without
`--conn-state-not-copied`: Go 11 alerts, Rust 9, two timing-dependent on each side. Every difference came from the installed
Go package being older than the shadow binary (the ATT&CK tags of c6b2b60 and lan-watch's own wording of 6356758 were in
the Rust build only); with those two fields set aside the alerts matched, and the one connection-log alert only Go had is
the "one poll only" kind the tool classes as expected. Over the ten hours since the reboot the Go daemon used 40 s of CPU
and 43 MB resident (733 MB in its cgroup with the page cache), the Rust one 19 s and 14 MB. Limbo's contract tests passed
with the Rust binary (integration-quarantine 71 of 71, integration-chain 33 of 33 with the Sarina advisory checks), and the
switch went ahead the same morning.

## Reading the connection log

The connection watch (`connection-watch` and, for a remote-access tool, `remote-access` alerts on `new_connection`) reads
/proc/net every 10 seconds in each daemon, at each daemon's own moment, and reports each (process, address, port) once, then
remembers it in `connections-state.json`. Three things make its alerts differ without a bug, and `shadow-compare.py` has a
rule for each (its header has the exact rules):

1. The first connection each daemon saw to a destination may be another socket of it (another local port, another process of
   the same name): compared without the socket's and process's own fields.
2. A connection short enough to fall between one daemon's polls is reported by the other only ("one poll only"). Expected
   only while both sides miss about equally; the tool prints the counts per address family, scope and named/unnamed owner,
   and a lopsided group (one daemon missing far more, which a port bug would cause) is a difference.
3. A shadow week started without the Go daemon's `connections-state.json` (step 3 did not copy it before 2026-11-18): the
   shadow daemon learned only the connections open at its first look, then reported every destination the Go daemon had
   learned weeks before. `--conn-state-not-copied` counts those as expected (only in the shadow log, a destination the Go
   log reported before the window). Do not pass it for a shadow week that copied the file: then such an alert would be the
   shadow daemon failing to read the state.

## Stop the shadow week

```bash
sudo systemctl disable --now heimdall-shadow
sudo rm -r /etc/systemd/system/heimdall-shadow.service /etc/systemd/system/heimdall-shadow.service.d
sudo systemctl daemon-reload
# keep /var/lib/heimdall-rs for the comparison, or: sudo rm -r /var/lib/heimdall-rs /etc/heimdall/shadow-config.json
```
