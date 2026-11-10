# Shadow mode: the Rust daemon beside the Go one for a week

`heimdalld-rs run --shadow` reads the real sources and writes its own alert log; it takes **no responses** (no Limbo hold,
no containment request, no copy of a held file, nothing to a mesh peer) and serves no API. The Go `heimdall.service` stays
as it is and stays in charge. After a week, `shadow-compare.py` compares the two alert logs. Plan and proofs so far:
`docs/RUST_PORT.md`.

What the shadow daemon watches: Sarina's sessions and vault notes (inotify), Limbo's event log, the FIM list
(`fim_paths`), host telemetry, the maintenance window, the /proc/net watchers (ecosystem ports, connections with the IP
databases and threat lists, new listeners), the journal (firewall blocks, SSH logins; one `journalctl --follow`), the
Wi-Fi results and router watch, the trusted network's device events and remote-access tools (packages, tunnels, programs),
through every detector, the verifier, the explanations, the tool rules and maintenance softening. **Not yet** (logged at
start; the comparison leaves their detectors out): the 6-hourly package, kernel and hardening audits, trust, the
correlator's incidents.

The journal needs the `systemd-journal` group, as the Go daemon has it from its firewall drop-in: copy that drop-in too
(step 4 below copies every drop-in of `heimdall.service`).

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
for f in agent-sessions.json vault-notes.json agent-baseline.json fim.json limbo-offset; do
  sudo test -e /var/lib/heimdall/$f && sudo install -o heimdall -g heimdall -m 0600 /var/lib/heimdall/$f /var/lib/heimdall-rs/$f
done
# (fim.json and limbo-offset: only if /etc/heimdall/config.json names them there; check fim_state_path, limbo_state_path)

# 4. the unit, with the same read access as the Go daemon (its drop-ins: Limbo's group, the connection read rights)
sudo install -Dm644 packaging/arch/heimdall-shadow.service /etc/systemd/system/heimdall-shadow.service
sudo mkdir -p /etc/systemd/system/heimdall-shadow.service.d
sudo cp /etc/systemd/system/heimdall.service.d/*.conf /etc/systemd/system/heimdall-shadow.service.d/ 2>/dev/null || true
sudo cp /usr/lib/systemd/system/heimdall.service.d/*.conf /etc/systemd/system/heimdall-shadow.service.d/ 2>/dev/null || true
sudo systemctl daemon-reload
sudo systemctl start heimdall-shadow
date -u +%Y-%m-%dT%H:%M:%SZ > ~/heimdall-shadow-start.txt   # the comparison's start
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
before the switch (the alert lines are real data: keep them private, do not paste them into an issue). Put the CPU and
memory readings and the comparison's summary lines in `progress.md`.

## Stop the shadow week

```bash
sudo systemctl disable --now heimdall-shadow
sudo rm -r /etc/systemd/system/heimdall-shadow.service /etc/systemd/system/heimdall-shadow.service.d
sudo systemctl daemon-reload
# keep /var/lib/heimdall-rs for the comparison, or: sudo rm -r /var/lib/heimdall-rs /etc/heimdall/shadow-config.json
```
