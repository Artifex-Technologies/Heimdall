# The switch: heimdalld becomes the Rust daemon

A plan, not done. The Go daemon stays in charge until every item under "Before" is true. Port status and proofs:
`docs/RUST_PORT.md`; the shadow week: `docs/RUST_SHADOW.md`.

## What changes

- `/usr/bin/heimdalld` is the Rust binary (built from `rust/`, today's `heimdalld-rs`). It runs the daemon (`run`) and
  **every one-shot command** (2026-11-11: scan, scan-files, lan, immunity, contain, grant, mesh, trust, origin, intel-check,
  ipdb-check, kernel-check, wifi-health, maintenance, remote, version, help; `docs/RUST_CLI.md`), each proved against the
  Go binary in fake roots with the same arguments, output, files and exit codes. So the units that call `heimdalld lan
  scan`, `heimdalld immunity inventory`, `heimdalld immunity run-requests` and `heimdalld contain run-request`, the pacman
  hook, `heimdall-intel-update`, Settings and the owner's own commands keep working unchanged, now on Rust.
- **The Go binary is no longer needed by anything.** For the first week it stays, as `/usr/lib/heimdall/heimdalld-go`, only
  as the immediate rollback (below); nothing calls it. A week later (stage 2 below) the package stops building it and Go
  leaves the build entirely. The Rust `heimdalld` still hands a command it does not know to that path when the file is
  there (`main.rs`, tested in `tests/run.rs`), which after stage 2 never happens: an unknown command gets Go's own
  "unknown command" message and exit code 2.
- Still not Rust, and not needing the Go binary: `heimdall-intel-update` (shell; curl and the checks above),
  `heimdall-dns-blocklist` and `heimdall-enable-defaults` (shell).
- The Wi-Fi helpers `heimdall-wifi-check`, `heimdall-wifi-guard`, `heimdall-wifi-notify` are ported (2026-11-11,
  `docs/RUST_CLI.md`, "Wi-Fi helpers"): the Rust `heimdalld` answers to their names (`cli::tool`). The package change that
  installs them as links, with the Python programs kept as the fallback, is on the branch `wifi-helpers-rust` (below),
  pushed and not merged: it goes in with stage 1 or after it, never before the shadow week is done.
- `heimdall.service` does not change (`ExecStart=/usr/bin/heimdalld run --config /etc/heimdall/config.json`), nor its
  drop-ins, nor the config, nor any state file: the Rust daemon reads and writes the Go daemon's files in
  `/var/lib/heimdall` (proved by the handover rehearsal, Go -> Rust -> Go -> Rust, no repeated alert), and the commands keep
  Go's files (immunity's store, the lock, the device list, trust's list, the mesh keys; `docs/RUST_CLI.md`).
- The shadow unit and `/usr/local/bin/heimdalld-rs` go away.

## Before (all must be true)

1. **The shadow week came back clean**: `shadow-compare.py` says "NO DIFFERENCE in the compared detectors", and the CPU and
   memory readings are in `progress.md` (`docs/RUST_SHADOW.md`, "After a week").
2. **What the Go daemon does in charge that is not ported yet is either ported or not used on this computer.** Check:

   ```bash
   sudo grep -E '"(sarina_url|mesh_listen|limbo_control_socket|limbo_auto_quarantine)"' /etc/heimdall/config.json
   ls -l /etc/heimdall/mesh-peers.json /etc/heimdall/contain.json 2>&1
   heimdalld trust status 2>&1 | head -3
   ```

   | Go daemon part | Needed when | Rust state |
   | --- | --- | --- |
   | the Limbo responder | `limbo_control_socket` set and `limbo_auto_quarantine` true | **ported** (`src/response.rs`) |
   | the Sarina advisory on a new hold | the above and `sarina_url` set | **ported** (`src/advisor.rs`) |
   | containment requests (`contain.Trigger`) | `/etc/heimdall/contain.json` switches it on | **ported** (`src/contain.rs`) |
   | the request to copy files Limbo held (`takeHeld`) | always, in charge (owner decision 2026-11-05) | **ported** (`immunity::TakeHeld`) |
   | mesh | `mesh_listen` set or peers enrolled | **ported** (`src/mesh.rs`) |
   | trust (the signed manifest of the agents' behaviour files) | trust mode not `off` | **ported** (`src/trust.rs`; reading and judging, as the daemon does; signing stays with `heimdalld trust`, Go) |

   Every row is ported (2026-11-10), so nothing here waits on the port any more; the commands above only show which parts
   the switch puts to work on this computer.
3. **Limbo's restrict-only contract tests pass against the Rust binary** (both need root and a real guest; run them
   yourself):

   ```bash
   # Limbo's sockets: no route loosens a hold, as real unprivileged users (independent of which Heimdall runs)
   sudo ~/Documents/Github/Limbo/scripts/integration-quarantine.sh
   # the whole chain with the Rust heimdalld in place of the Go one (the script builds Go's; this copy installs ours)
   cd ~/Documents/Github/Heimdall/rust && scripts/nicecargo.sh build --release --locked && cd -
   cd ~/Documents/Github/Limbo/scripts && \
     sed 's#( cd "$HEIMDALL_REPO" \&\& go build -o "$WORK/bin/heimdalld" ./cmd/heimdalld )#install -m755 "$HEIMDALL_REPO/rust/target/release/heimdalld-rs" "$WORK/bin/heimdalld"#' \
       integration-chain.sh | sudo bash -s
   ```

   With the Sarina advisory ported, every check of the chain must pass with the Rust binary, the six advisory checks ("an
   advisory from Sarina was attached" through "the evidence reached the model fenced as untrusted") included.
4. `cd rust && scripts/nicecargo.sh test --offline` and `go test ./...` pass at the commit the package is built from.

## The package change (heimdall-git; both PKGBUILDs call `packaging/install.sh`)

Made in the same commit as the switch, not before (a package built from it installs the Rust daemon).

**Stage 1 (the switch):**

- `makedepends`: add `rust` (cargo); keep `go` for this stage. `depends` unchanged (the Rust binary links only glibc, libm,
  libgcc_s).
- `build()`:

  ```bash
  go build -trimpath -ldflags "-s -w" -o heimdalld-go ./cmd/heimdalld
  (cd rust && cargo build --release --locked --offline || cargo build --release --locked)
  ```

  (`--offline` first so a build with the crates already fetched never reaches the network; `prepare()` may run
  `cargo fetch --locked` instead.)
- `packaging/install.sh`: the line `i 755 heimdalld usr/bin/heimdalld` becomes

  ```text
  i 755 rust/target/release/heimdalld-rs        usr/bin/heimdalld
  i 755 heimdalld-go                            usr/lib/heimdall/heimdalld-go
  ```

  and `packaging/tests` gets a check that both are installed. The pacman hook (`Target = usr/bin/heimdalld`) stays.
- LykanOS and Labyrinth images get the same package; nothing else in them changes.

**The Wi-Fi helpers (branch `wifi-helpers-rust`, merged at stage 1 or later):**

- The branch builds the Rust binary (`makedepends` gains `rust`; `build()` runs the cargo line above) and installs it as
  `/usr/lib/heimdall/heimdalld-rs`, then `/usr/bin/heimdall-wifi-check`, `heimdall-wifi-guard` and `heimdall-wifi-notify`
  as links to it. The Python programs stay installed as `/usr/lib/heimdall/python/heimdall-wifi-*` (the fallback). The
  units and the dispatcher scripts are unchanged: they call the same paths.
- A recipe that builds only Go (Labyrinth's `heimdall-git` today, which calls the same `install.sh`) keeps installing the
  Python programs at `/usr/bin` as before (`install.sh` says so on standard error), so merging never breaks a sibling's
  package; Labyrinth's recipe gets the cargo line with the stage-1 change.
- Merged on its own (before the stage-1 commit), it changes only the helpers: `/usr/bin/heimdalld` stays Go. Merged with or
  after stage 1, the stage-1 commit's `usr/bin/heimdalld` line and the branch's `usr/lib/heimdall/heimdalld-rs` line
  install the same file; the links may then point at `heimdalld` and the second copy go (a one-line change in
  `install.sh`, with the packaging test that checks the links).
- `packaging/tests/test_install_layout.py` runs `install.sh` into a temporary folder and checks the links resolve to the
  Rust binary and the fallbacks are there.
- Checks on this computer after installing (what the tests cannot do; each read-only or on a network I choose):

  ```bash
  ls -l /usr/bin/heimdall-wifi-*                       # links to /usr/lib/heimdall/heimdalld-rs
  heimdall-wifi-guard status                          # the trusted networks, the VPN, "now on: ...", as before
  sudo systemctl start heimdall-wifi-check@$(nmcli -g GENERAL.CON-UUID device show wlan0).service
  journalctl -u 'heimdall-wifi-check@*' -n 20 --no-pager   # the check under its sandbox (SystemCallFilter=@system-service)
  tail -n 2 /var/lib/heimdall/wifi/results.jsonl      # the same checks and verdict as the Python's line before it
  cat /run/heimdall-wifi/last.json                    # and the notification shown on the desktop
  ```

  The guard's `pre-up`/`up`/`down` with a VPN set up (the lockdown, the VPN, the kill switch) on an untrusted network I
  join on purpose, never while the PC is streaming.
- Rollback of one helper at once (lasts until the next package upgrade):
  `sudo ln -sfn /usr/lib/heimdall/python/heimdall-wifi-guard /usr/bin/heimdall-wifi-guard` (likewise `-check`,
  `-notify`); fully: the previous package from pacman's cache.

**Stage 2 (a week after the switch, when nothing went back to Go):** the Go binary goes.

- `makedepends`: drop `go`. `build()`: only the cargo line. `packaging/install.sh`: drop the `heimdalld-go` line (the
  packaging test checks it is gone). The rollback is then the previous package from pacman's cache (below).
- The Go sources stay in the repository as the reference the parity fixtures are written from (`internal/parity`,
  `go test ./internal/parity -update`) until a later decision retires them; they are no longer shipped.

## The switch, on my PC

```bash
cd ~/Documents/Github/Heimdall && git pull
# 1. the shadow daemon off (it must not run beside the daemon in charge)
sudo systemctl disable --now heimdall-shadow
# 2. build and install the package (Labyrinth's heimdall-git), keeping the old one in pacman's cache for the rollback
cd ~/Documents/Github/Labyrinth_OS/packages/pkgbuilds/heimdall-git && makepkg -f
ls /var/cache/pacman/pkg/heimdall-git-* | tail -2          # note the previous version's file
sudo pacman -U heimdall-git-*.pkg.tar.zst
sudo systemctl daemon-reload && sudo systemctl restart heimdall
# 3. check
heimdalld version; /usr/lib/heimdall/heimdalld-go version   # both "heimdalld 0.1.0"
journalctl -u heimdall -n 40 --no-pager                    # the sources it watches; "status API listening"; "Limbo quarantine response enabled", "mesh on as", "trust watch" where they apply
curl -s http://127.0.0.1:8930/healthz                      # ok
curl -s 'http://127.0.0.1:8930/v1/alerts?n=3' | head -c 400; echo
heimdalld lan list | head -3                               # a one-shot command, now Rust's
sudo systemctl start heimdall-lan-scan.service; journalctl -u heimdall-lan-scan -n 5 --no-pager   # the scan under its sandbox
sudo systemctl start heimdall-inventory.service; journalctl -u heimdall-inventory -n 3 --no-pager  # "inventory: N programs"
heimdalld contain status; heimdalld trust status | head -3; heimdalld wifi-health --json | head -c 200; echo
pid=$(systemctl show -p MainPID --value heimdall)
grep -E '^(VmRSS|Threads)' /proc/$pid/status; sudo grep -E '^Pss:' /proc/$pid/smaps_rollup
# 4. tidy the shadow week away
sudo rm -r /etc/systemd/system/heimdall-shadow.service /etc/systemd/system/heimdall-shadow.service.d
sudo rm /usr/local/bin/heimdalld-rs /etc/heimdall/shadow-config.json
sudo systemctl daemon-reload
# keep /var/lib/heimdall-rs until the comparison is written up, then: sudo rm -r /var/lib/heimdall-rs
```

## Rollback

The state files are the same for both daemons, so going back loses nothing and repeats no alert.

- **At once, without a package** (stage 1 only: a drop-in that runs the Go binary the package kept):

  ```bash
  sudo systemctl edit heimdall      # write these three lines, save
  #   [Service]
  #   ExecStart=
  #   ExecStart=/usr/lib/heimdall/heimdalld-go run --config /etc/heimdall/config.json
  sudo systemctl restart heimdall
  ```

  Undo it with `sudo systemctl revert heimdall && sudo systemctl restart heimdall`.
- **Fully** (the previous package from pacman's cache): `sudo pacman -U /var/cache/pacman/pkg/heimdall-git-<previous>.pkg.tar.zst`
  then `sudo systemctl daemon-reload && sudo systemctl restart heimdall`.

## Checklist

- [ ] Shadow week: "NO DIFFERENCE"; CPU and PSS of both daemons in `progress.md` (if trust mode is not `off` on this
      computer, the shadow binary must be the one from 2026-11-10 or later: `docs/RUST_SHADOW.md`, "Updating the binary")
- [x] Every row of the table under "Before" is ported (2026-11-10: the responder, the Sarina advisory, containment
      requests, takeHeld, the mesh, trust)
- [ ] `integration-quarantine.sh` passes; `integration-chain.sh` with the Rust binary passes (every check, the six
      advisory checks included)
- [ ] Rust and Go test suites pass at the commit the package is built from (they pass at the last port commit of
      2026-11-10; `tests/mesh.rs` needs Go on the PATH to run the Go node, and says so when it skips)
- [ ] Package change committed (PKGBUILD makedepends, build, install.sh, packaging test); Coordination Log entry for
      Labyrinth, LykanOS, Sarina, Limbo, Yggdrasil (nothing for them to change)
- [ ] Shadow unit disabled; package built and installed; `heimdall` restarted
- [x] Every one-shot command ported and proved against Go (2026-11-11, `docs/RUST_CLI.md`)
- [ ] Checks: version of both binaries, the start log, /healthz, /v1/alerts, the one-shot commands above (lan scan and the
      inventory under their sandboxed units), Settings' Security page shows alerts, the device list and the Wi-Fi check,
      PSS and threads
- [ ] Wi-Fi helpers: branch `wifi-helpers-rust` merged with stage 1 or later; `test_install_layout.py` passes; the checks
      above (the check under its unit on a real network, the guard's status, the notification), and once the guard on an
      untrusted network with the VPN; a week later, the Python fallbacks can go with stage 2
- [ ] Stage 2, a week later: the package stops building Go (`makedepends` without `go`, `install.sh` without
      `heimdalld-go`); Coordination Log entry
- [ ] A day later: no `integration` alerts from the daemon itself; CPU over the day; then the shadow leftovers removed
