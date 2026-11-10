# The switch: heimdalld becomes the Rust daemon

A plan, not done. The Go daemon stays in charge until every item under "Before" is true. Port status and proofs:
`docs/RUST_PORT.md`; the shadow week: `docs/RUST_SHADOW.md`.

## What changes

- `/usr/bin/heimdalld` is the Rust binary (built from `rust/`, today's `heimdalld-rs`). It runs the daemon (`run`) itself.
- The Go binary stays, as `/usr/lib/heimdall/heimdalld-go`, for every one-shot command not ported (scan, scan-files, lan,
  immunity, contain, grant, mesh, trust, origin, intel-check, ipdb-check, kernel-check, wifi-health, maintenance, remote,
  version). The Rust `heimdalld` hands any command it does not know to it, with the same arguments and exit code
  (`main.rs`, tested in `tests/run.rs`). So the units that call `heimdalld lan scan`, `heimdalld immunity inventory`,
  `heimdalld immunity run-requests` and `heimdalld contain run-request`, the pacman hook, Settings and the owner's own
  commands keep working unchanged. Porting them is later and optional: each is small and runs seconds a day.
- `heimdall.service` does not change (`ExecStart=/usr/bin/heimdalld run --config /etc/heimdall/config.json`), nor its
  drop-ins, nor the config, nor any state file: the Rust daemon reads and writes the Go daemon's files in
  `/var/lib/heimdall` (proved by the handover rehearsal, Go -> Rust -> Go -> Rust, no repeated alert).
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
   | the Sarina advisory on a new hold | the above and `sarina_url` set | open (`internal/response/advisor.go`) |
   | containment requests (`contain.Trigger`) | `/etc/heimdall/contain.json` switches it on | open (`internal/contain`) |
   | the request to copy files Limbo held (`takeHeld`) | always, in charge (owner decision 2026-11-05) | **ported** (`immunity::TakeHeld`) |
   | mesh | `mesh_listen` set or peers enrolled | open (step 4) |
   | trust (the signed manifest of the agents' behaviour files) | trust mode not `off` | open (step 4) |

   The switch waits for every row that is needed here. (The daemon in charge logs at start which of these it does not do
   yet.)
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

   Until the Sarina advisory is ported, the chain's six advisory checks ("an advisory from Sarina was attached" through
   "the evidence reached the model fenced as untrusted") fail with the Rust binary; every other check must pass.
4. `cd rust && scripts/nicecargo.sh test --offline` and `go test ./...` pass at the commit the package is built from.

## The package change (heimdall-git; both PKGBUILDs call `packaging/install.sh`)

Made in the same commit as the switch, not before (a package built from it installs the Rust daemon):

- `makedepends`: add `rust` (cargo). `depends` unchanged (the Rust binary links only glibc, libm, libgcc_s).
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
heimdalld version; /usr/lib/heimdall/heimdalld-go version
journalctl -u heimdall -n 40 --no-pager                    # the sources it watches; "status API listening"; what it does not do yet
curl -s http://127.0.0.1:8930/healthz                      # ok
curl -s 'http://127.0.0.1:8930/v1/alerts?n=3' | head -c 400; echo
heimdalld lan list | head -3                               # a one-shot command, through the Go binary
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

- **At once, without a package** (a drop-in that runs the Go binary the package kept):

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

- [ ] Shadow week: "NO DIFFERENCE"; CPU and PSS of both daemons in `progress.md`
- [ ] Every row of the table under "Before" that is needed on this computer is ported
- [ ] `integration-quarantine.sh` passes; `integration-chain.sh` with the Rust binary passes (but the advisory checks
      while the advisory is not ported)
- [ ] Rust and Go test suites pass at the commit
- [ ] Package change committed (PKGBUILD makedepends, build, install.sh, packaging test); Coordination Log entry for
      Labyrinth, LykanOS, Sarina, Limbo, Yggdrasil (nothing for them to change)
- [ ] Shadow unit disabled; package built and installed; `heimdall` restarted
- [ ] Checks: version of both binaries, the start log, /healthz, /v1/alerts, a one-shot command, Settings' Security page
      shows alerts and the device list, PSS and threads
- [ ] A day later: no `integration` alerts from the daemon itself; CPU over the day; then the shadow leftovers removed
