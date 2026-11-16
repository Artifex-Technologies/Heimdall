# Location sounds: aircraft overhead and mains hum

A recording can give away where and when it was made through sounds nobody notices:

- **Aircraft overhead.** A propeller or engine tone glides down in pitch as a plane passes (Doppler). The exact shape of
  that curve depends on where the listener stood. Matched against public flight tracks (ADS-B), one minute of audio with an
  aircraft nobody could hear places a recording to within a few hundred metres. colsto showed it
  ([video](https://www.youtube.com/watch?v=UytYrhYLOKI)); flyover-scrub replicated it on real phone videos and built the
  defence this is a Rust rewrite of.
- **Mains hum (ENF).** The grid's 50 or 60 Hz wanders by hundredths of a hertz, the same at every socket of one grid. Hum
  that a microphone picks up records that wander, so a few minutes of it can be matched against a grid log to date a
  recording, and its 50 or 60 says which grid it was made on.

I wanted this protected on everything the microphone records on my computer: recordings, videos, and live calls in Teams,
Zoom, Meet in the browser, Webex, Discord. Heimdall does it in two places:

| | What | How |
| --- | --- | --- |
| **The private microphone** | every call and recording, live | "Microphone (private)" is the real microphone scrubbed as it is recorded (21 ms added); WirePlumber makes it the input every app records, and hides the real one |
| **`heimdall-scrub`** | files: audio, and the sound of videos | a scrubbed copy with lookahead; the video copied untouched; metadata (GPS, dates, device) removed. In Minos: right-click > Scrub location sounds |

Both keep speech and everything above 2 kHz. In the band where aircraft tones and hum live (20 Hz to 2 kHz) they
re-synthesise the quiet background with fresh noise at the same level, remove long slowly gliding tones and steady mains
harmonics, and leave loud foreground (a voice) untouched. It is evidence, not a guarantee: read [the limits](#limits).

## The package

Everything here is in its own package, `heimdall-private-mic-git` (provides `heimdall-private-mic`), not in heimdall-git:
every Labyrinth OS and LykanOS install gets it, with or without Heimdall (I decided that on 2026-11-15). The two packages
share no file; `packaging/install.sh DESTDIR private-mic` is its file list, beside heimdall-git's in the same script.

## Using it

```bash
heimdall-scrub holiday.mov "holiday (scrubbed).mov"   # a scrubbed copy; the original is never touched
heimdall-scrub --check holiday.mov                    # report gliding tones and mains hum, write nothing
heimdall-private-mic status                           # on (every app records the scrubbed microphone)
heimdall-private-mic off                              # e.g. to record music with full bass; `on` to switch back
```

- `heimdall-scrub IN OUT`: never writes over IN, and not over an existing OUT without `--force`. `--keep-hum` keeps steady
  tones; `--keep-metadata` keeps tags; `--live` uses the live algorithm on a file; `--progress` prints `progress 0.42`
  lines (Minos reads them); a stop (SIGTERM) removes its temporary files. ffmpeg decodes and encodes; the video stream is
  copied packet for packet (checked: identical), cover pictures and data/subtitle streams are dropped (a picture can carry
  its own GPS), and every tag, chapter and the encoder name are removed. File names reach ffmpeg as `file:/path`, so a name
  like `-x.mp4` is only ever a file.
- The private microphone is on by default. Settings > Security > Privacy (and Peripherals > Microphone) has the switch;
  `heimdall-private-mic on|off` does the same. Off takes effect at once (no restart) and is remembered.

## How the private microphone is enforced

The filter runs inside PipeWire itself (module-filter-chain with the `heimdall_scrub` LADSPA plugin; no extra process). A
WirePlumber script (`heimdall/private-mic.lua`) then does three things while `heimdall.private-mic.enforce` is on:

1. **Default.** The private microphone is the default input. My own choice stays stored as the configured default and is
   what the private microphone listens to; it is the default again when I switch enforcement off.
2. **Linking.** Any recording stream WirePlumber would link to a device microphone (an app that picks a device by name, a
   remembered per-app choice, an ALSA or JACK program going through PipeWire) is linked to the private microphone instead.
   The filter's own input is the only stream that reaches a device microphone.
3. **Hiding.** Ordinary PipeWire clients get no permission on device microphones, so device lists offer only "Microphone
   (private)" and nothing can link to a device microphone by hand. pipewire-pulse is one such client, which covers every
   PulseAudio app: browsers (Meet), Teams, Zoom, Webex, Discord, OBS.

Tested end to end in a PipeWire and WirePlumber of their own (never my desktop's), `packaging/privacy/isolated-test.sh`:
the default recording and a recording that asked for the device microphone by name both came from the private
microphone; a client listing nodes did not see the device microphone and a manual link to it was refused ("Operation not
permitted"); with enforcement off the device microphone was visible and the default again; the feed had 60 Hz mains hum
(ENF present, +40 to +49 dB) and both recordings had none. PipeWire reports the filter's latency (1024 samples).

**Sarina.** On Labyrinth OS there is no exception: Sarina's voice input records the private microphone like every app
(speech is kept, and an exception would be something to bypass). On LykanOS it is my choice: a setting, off by default,
lets only Sarina's voice input record the real microphone (Settings > Security > Privacy there, or
`heimdall-private-mic sarina-raw on|off`); every other app stays private. How it is kept off Labyrinth:

- The setting is declared in a WirePlumber fragment of its own (`/usr/share/heimdall-private-mic/lykanos.conf`, which also
  carries a marker the script checks). The package's pacman hook runs `heimdall-private-mic os-setup`, which links it into
  `/etc/wireplumber/wireplumber.conf.d/` only where `/etc/os-release` says `ID=lykanos`, and removes its own link elsewhere
  and when the package goes. Without the fragment the setting does not exist, and even forcing it by hand changes nothing
  (tested).
- Sarina's stream is the one Yggdrasil's panel starts for Super+S, marked `heimdall.private-mic.exempt = "sarina-voice"`.
  A program running as me could put the same mark on its own stream; with the setting on (LykanOS only) it would get the
  real microphone. That is the price of the option, which is why it is off by default.

Tested in the isolated PipeWire as Labyrinth (Sarina's stream got the private microphone, also with the setting forced) and
as LykanOS (off: private; on: Sarina's stream had the device microphone's hum, while a recording asking for the device
microphone by name and the default recording stayed private).

Trade-offs I accepted:

- **A plugin fault cannot leak.** If the filter ever fails, it outputs silence: a call goes quiet rather than unscrubbed.
  It never allocates or locks on PipeWire's real-time thread. It runs inside the PipeWire daemon, so a crash there would
  restart my audio; it has no allocation, recursion or I/O in its processing path to crash on.
- **Music.** Sustained notes are long steady tones, and the band below 2 kHz is re-synthesised where quiet. Switch it off to
  record instruments.
- **Mono.** The private microphone is one channel (a stereo microphone is mixed down first): half the work, and calls are
  mono anyway.

## Limits

- **Other devices and other people's files.** It protects what this computer records. A phone, a camera, a doorbell or a
  call partner's own recording of me are untouched; a file I receive is only scrubbed if I scrub it (`heimdall-scrub`).
- **Direct sound-card access.** A program that opens the sound card itself (ALSA `hw:`, while PipeWire is not using it)
  bypasses PipeWire and so the scrub. Ordinary apps do not do this; a hostile program running as me could. The same goes for
  anything that can read my session's memory.
- **The first milliseconds of a client.** Permissions are applied by WirePlumber just after a client connects; a program that
  links a device microphone by hand within those milliseconds could get it (the isolated test saw a short-lived `pw-dump` list
  it). Linking done by WirePlumber is always redirected. Flatpak/portal clients keep their own permission rules (their audio
  goes through pipewire-pulse, which is covered).
- **Loud speech over a flyover.** Where a voice is loud, its bins are kept, and an aircraft tone under the same bins is kept
  with them. In the tests the residual did not score, but a loud flyover under continuous speech is the most likely leak.
- **The live mode starts late on a sudden line.** A tone must last 1.5 s before it counts as a ridge (the whole-file mode
  looks ahead). It is followed from 4 dB above the floor, far below what is kept as foreground, so a flyover that fades in is
  usually removed long before it is audible; a loud tone that starts abruptly can pass for its first 1.5 s.
- **Indoors and outdoors.** Indoors the aircraft tone is weaker and the mains hum stronger (more appliances, wiring); outdoors
  the reverse. Both are handled the same way, but the measurements here are on synthetic audio only, not on real recordings
  of me (none are in the repository). The reference project's own results on real phone videos are its, not mine.
- **Other signatures.** Only the band 20 Hz to 2 kHz is changed. Bird song, church bells, sirens or a recognisable room are
  not location sounds this addresses, and metadata is removed only from files through `heimdall-scrub`.
- **Not a guarantee.** Tested against the two scorers (brightness and trace-and-fit) on synthetic flyovers; not against
  learned detectors or several flights with a locked clock offset.

## Planned

- **Vehicle and transit sounds:** a wider band and short tonal events (tram bells, door chimes, horns, rail squeal), tested on
  synthetic tram, rail and bus sounds.
- **"Voice only":** keeps any voice and removes everything else, stop announcements included (no profile needed; also on a
  Raspberry Pi).
- **"My voice only":** keeps only my voice, steered by the same voiceprint Sarina enrols for its speaker check, so one
  enrolment serves every program. Off until I turn it on; the voiceprint stays in Sarina's encrypted store. Design: Sarina's
  docs/VOICE_AND_TRUST_PLAN.md, section 9.
- **The real microphone out of my account's reach:** a small system service with its own account owns the device, so
  programs that open the sound card directly, or hostile programs running as me, only ever see the private microphone.

## Measured (2026-11-15, synthetic audio only)

The tests (`rust/flyover-attack/tests/scrub_defeats_scorer.rs`, run with `--nocapture` for the numbers) build an 80 s scene
at 48 kHz: a physically modelled propeller flyover (700 m up, 70 m/s, a gentle turn, emission-time Doppler) at -28 dB
(inaudible) or -10 dB against the room, a voice (syllables, pitch 125-175 Hz gliding up to 160 Hz/s, 30 harmonics under
three formants), room noise and 60 Hz mains hum wandering a few hundredths of a hertz. The attacker gets the exact track,
a 9 x 9 grid of places 500 m apart around the truth, a clock offset sweep and a source-pitch sweep.

| | raw | whole-file scrub | live scrub |
| --- | --- | --- | --- |
| brightness scorer, -28 dB flyover: truth's rank / signal vs chance | 1 of 81 / 10.2x | 58 of 81 / 1.0x | 48 of 81 / 0.8x |
| -10 dB flyover | 1 of 81 / 37.0x | 42 of 81 / 1.2x | 38 of 81 / 0.9x |
| truth's lead over the no-aircraft control (-28 / -10 dB) | +0.44 / +2.93 | -0.05 / -0.02 | +0.03 / +0.03 |
| trace-and-fit, -10 dB: line followed | 218 frames, 112 m off, reversal 85 | 4 frames (nothing to fit) | 5 frames |
| mains hum (ENF) | present, 60 Hz, +28 to +35 dB | not detected | not detected |
| above 2.2 kHz: signal to change | | 120 dB (sample for sample) | 81 dB |
| voice 300 Hz-2 kHz against what changed there | | 18.2 dB | 23.1 dB |
| ... where the voice is 20 dB above the room | | 21.7 dB | 25.7 dB |
| room tone alone, level change 300 Hz-2 kHz / 20-300 Hz | | -0.07 / -0.17 dB | +0.03 / -0.52 dB |

"Signal vs chance" compares the best place with the same search on the time-reversed spectrogram, where an aircraft line
rises instead of falling and can only match by chance; about 1 is chance, 4 or more is a real line. The -28 dB flyover is
too faint for trace-and-fit even raw (it needs a visible line).

CPU and latency (`rust/scrub/tests/cpu.rs`, release build, Intel i9-9900K, one channel at 48 kHz, a busy input with hum and
gliding tones): the live scrub takes **1.4 % of one core** and adds **1024 samples (21.3 ms)**; the whole-file scrub runs
about 60x faster than real time. The DSP has no dependencies and no SIMD; I have not measured it on a Raspberry Pi. By
the usual ratio of a Cortex-A72 core to this one (5-8x slower) I expect about 7-11 % of one Pi 4 core per channel.

## How it works

`rust/scrub` (heimdall-scrub):

- **Whole-file** (`offline.rs`, the reference algorithm): a 0.17 s STFT (8192 points at 48 kHz). The floor is the median of
  log magnitude across 120 Hz, smoothed over 3 s; bins under 12 dB above it are background and re-synthesised with
  random-phase noise at the floor's level; long ridges (4 dB up, at least 1.5 s, gliding at most 40 Hz/s) are removed with
  8 Hz each side; the rest is kept. Streamed in one-minute blocks with ten seconds of context, so an hour of audio needs
  megabytes; the output is the input plus the change, so everything outside the band is the input sample for sample.
- **Live** (`live.rs`, `analysis.rs`, `stage.rs`): causal. A slow look at the past (0.25 s spectra every 64 ms at 8 kHz)
  follows lines and the grid frequency; each ridge confirmed after 1.5 s, and each mains harmonic that stood above the
  floor for most of two seconds, gets a narrow notch that removes it and refills the gap with noise at the floor's level.
  Then a 1024-point STFT re-synthesises the quiet part of the band (minimum-statistics floor over 1.5 s), so a line under
  the noise, the one a matched filter digs out, is gone.
- Two departures from the reference, both measured: the replacement noise is at the floor's level instead of the local
  mean (which spread a voice's quiet parts into the pauses: +6 dB room tone between words), and fresh noise goes back into
  the STFT 6 dB louder (frames of independent noise overlap-add to a quarter of their power: the room tone came out 6 dB
  quiet without it).

`rust/scrub-ladspa`: the live scrub as a LADSPA plugin (`heimdall_scrub`, ports Input, Output, latency).
`rust/flyover-attack`: the attack (brightness scorer, trace and fit, emission-time physics) as a library, so the defence is
measured instead of assumed: audio and flights in, ranked places out. It has no network code.

## Files

In `heimdall-private-mic-git` (recipes: Labyrinth_OS's `packages/pkgbuilds/heimdall-private-mic-git`, and
`packaging/arch-private-mic/PKGBUILD` here):

| Installed | From |
| --- | --- |
| `/usr/bin/heimdall-scrub`, `/usr/bin/heimdall-private-mic` | `rust/scrub` |
| `/usr/lib/ladspa/heimdall-scrub.so` | `rust/scrub-ladspa` |
| `/usr/share/pipewire/pipewire.conf.d/60-heimdall-private-mic.conf` | `packaging/privacy/pipewire-private-mic.conf` |
| `/usr/share/wireplumber/wireplumber.conf.d/60-heimdall-private-mic.conf` | `packaging/privacy/wireplumber-private-mic.conf` |
| `/usr/share/wireplumber/scripts/heimdall/private-mic.lua` | `packaging/privacy/private-mic.lua` |
| `/usr/share/heimdall-private-mic/lykanos.conf` (linked into `/etc/wireplumber/wireplumber.conf.d/` on LykanOS only) | `packaging/privacy/wireplumber-private-mic-lykanos.conf` |
| `/usr/share/libalpm/hooks/heimdall-private-mic.hook`, `heimdall-private-mic-remove.hook` (run `os-setup`) | `packaging/privacy/` |
| `/usr/share/licenses/heimdall-private-mic/` (LICENSE, NOTICE.flyover-scrub) | `LICENSE`, `rust/scrub/NOTICE` |

After installing, the private microphone appears when PipeWire and WirePlumber restart (log out and in, or
`systemctl --user restart pipewire wireplumber`).

## Credits

- [flyover-scrub](https://github.com/lizTheDeveloper/flyover-scrub) by lizTheDeveloper, MIT: the scrub algorithm, the ENF
  and ridge detectors, the physics and both scorers this is a rewrite of (read, not run; the MIT notice is in
  `rust/scrub/NOTICE` and installed with the package).
- colsto, *I discovered a sound that leaks your exact location (and it's everywhere)*: the attack, the emission-time Doppler
  model and the trace-and-fit method.
