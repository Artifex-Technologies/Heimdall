# Rust migration: what was ported and what it measured

The detailed record of the port: [RUST_PORT.md](RUST_PORT.md), and the switch from Go: my switch plan (in my private plans: docs/plans/PLAN_RUST_SWITCH.md).

The daemon, every command and the Python Wi-Fi helpers are ported to Rust ([`rust/`](../rust/README.md)), one binary that takes
over at the switch (planned in my private plans: docs/plans/PLAN_RUST_SWITCH.md). Measured on my desktop, old against new on the same input
(2026-11-11; a minus is a gain):

| Program | Was | Measured | Details |
| --- | --- | --- | --- |
| the daemon (`heimdalld run`) | Go | idle CPU 0.115 → 0.060 % of a core (−48 %), memory 39.8 → 13.6 MB (−66 %), context switches 21.9 → 0.4 a second, the engine 44 % faster; **worse: peak since start 49.3 → 73.3 MB (+49 %)** | [the daemon](../rust/README.md#the-daemon) |
| 17 one-shot commands | Go | most 1.8-2.3 ms → 0.6-1.0 ms (−57 to −70 %) and 15-17 MB → 3.4-6.2 MB peak; `scan` −10 %; **worse: `intel-check tracker` +28 %, `kernel-check` peak +14 %** | [the commands](../rust/README.md#the-one-shot-commands) |
| the Wi-Fi helpers (check, guard, notify) | Python | 23-49 ms → 0.6-3.3 ms (−89 to −97 %, 23-45 ms sooner each run), 14-23 MB → 4-5 MB | [the helpers](../rust/README.md#the-wi-fi-helpers) |

Every case gave the same output in both. What the port found and fixed on the way (an injection phrase hidden by a look-alike
letter, a device name that crashed `lan scan`, a private key briefly readable by other accounts, and more) is listed with
each.
