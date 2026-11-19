# Disguise my voice

A voice is an identifier. With the location sounds scrubbed ([LOCATION_SOUNDS.md](LOCATION_SOUNDS.md)), the voice itself
is the next thing that says who is talking: a colleague, a stranger who has heard me once, or a speaker-recognition model
that has a sample of me. "Disguise my voice" shifts the pitch and the formants of my voice on the private microphone (every
call and recording) or in a file, with a little slow variation, so it does not sound like me at a casual listen.

**What it is, honestly:** light signal processing. It hides casual recognition. Someone determined who knows (or guesses)
that it was used can partly undo it, by shifting the pitch and formants back by ear or by searching for the shift that
sounds most natural. It does not change what I say, my words, accent, rhythm, laugh or breathing, and a speaker-recognition
model may still match me, especially one trained on shifted voices. It is not a voice conversion. Off by default.

Approved by me on 2026-11-18 (R18 of my reference plan (in my private plans: Labyrinth_OS docs/plans/REFERENCE_PLAN_2026-11.md)), DSP first. A later phase may add
conversion to one of a few synthetic voices that belong to nobody (desktop GPU); never a voice taken from a real person.

## Using it

```bash
heimdall-private-mic disguise lower      # on, with the "lower" preset (every app recording the private microphone)
heimdall-private-mic disguise higher     # switch preset (glides, no click)
heimdall-private-mic disguise off        # back to my own voice at once
heimdall-private-mic disguise on         # on again with the last preset
heimdall-private-mic status --json       # ..."disguise":true,"disguise_preset":"lower"}
heimdall-scrub --disguise higher talk.mp4 "talk (disguised).mp4"   # a scrubbed and disguised copy of a file
```

Settings > Security > Privacy has the same switch ("Disguise my voice") with the preset, under the private microphone's
switch; it is shown while the private microphone is on (with it off, apps record the real microphone and the disguise
would reach only apps that pick "Microphone (private)" themselves).

The state lives where the private microphone's other switches live: two WirePlumber settings, saved, so they survive a
restart. `heimdall.private-mic.disguise` (on/off, default off) and `heimdall.private-mic.disguise-preset` ("lower" or
"higher", default "lower"). WirePlumber's script (`heimdall/private-mic.lua`) sets the filter's `disguise:Preset` control
from them at once, and again whenever the filter appears.

| Preset | Pitch | Formants | Sounds |
| --- | --- | --- | --- |
| lower | 3 semitones down | x 0.88 | deeper, a larger speaker |
| higher | 3 semitones up | x 1.12 | higher, a smaller speaker |

No free knobs: a few settled shapes are easier to choose and to test, and a free pitch knob invites the one setting that is
easiest to undo. Pitch and formants move together on purpose; moving only the pitch sounds like me with a cold.

**No fixed fingerprint.** Each session (each PipeWire start, each file) draws its own offset from the preset, up to 0.4
semitone and 2.5 % on the formants, from the operating system's randomness, and both wander slowly around it (a random
walk with a 1.5 s memory, about 0.25 semitone and 1.5 %, never more than 2.5 times that). Two calls are not the same exact
transformation, and the variation is never stored.

## Where it sits

```
real microphone -> scrub (location sounds) -> disguise -> "Microphone (private)" -> apps
```

Both are LADSPA plugins in the one PipeWire filter-chain (`packaging/privacy/pipewire-private-mic.conf`): `heimdall_scrub`
and `heimdall_disguise`, the second linked after the first. The scrub always runs; the disguise passes the voice through
sample for sample, with no delay, while it is off.

**Sarina and the voiceprint.** A speaker check (Sarina's) or "my voice only" must hear my real voice, so such a reader takes
the signal **before** the disguise, between the two nodes of the filter graph, never after it. Neither exists today. On Labyrinth OS Sarina records the private microphone
like every app, so while the disguise is on she hears the disguised voice (speech recognition copes with a three-semitone
shift; a speaker check would not). On LykanOS, with Sarina's real-microphone setting on, her voice input skips the whole
filter and is never disguised.

## How it works

`rust/scrub/src/disguise.rs`, written from the published methods (no code copied, so no notice):

- **Pitch: TD-PSOLA** (time-domain pitch-synchronous overlap-add, Moulines and Charpentier, 1990). A pitch tracker gives
  the period T every 5 ms. Analysis marks sit one period apart in the input; around each a grain is cut with a Hann window
  two periods wide (one glottal pulse with its formants). Synthesis marks sit T / p apart in the output (p the pitch ratio);
  each takes the latest analysis mark at or before it, so grains are repeated (up) or skipped (down) and the length and
  timing stay the same.
- **Formants: each grain resampled.** A grain is read at speed f (the formant ratio) before it is added, so its spectrum
  (the formants) is scaled by f while the spacing alone sets the pitch. The two knobs are independent by construction.
- **Pitch tracker: YIN** (de Cheveigne and Kawahara, 2002) on a copy decimated to 12 kHz, 70 to 450 Hz. The first dip of
  the normalised difference under 0.25, else the deepest under 0.4; a voice lost for a moment keeps its last period for
  60 ms (the scrub's noise in a voice's weak low harmonics made the tracker drop frames, which left parts of syllables
  undisguised).
- **Unvoiced sound** (breath, s, f, room noise) gets 5 ms grains at the same spacing in and out: no pitch change (a period
  imposed on noise would buzz), only the formant scaling.
- **Level.** The sum is divided by the sum of the windows; resampled grains overlap out of phase, which costs up to 2 dB,
  so a slow level match (0.3 s, at most -3 to +4 dB, held in silence) brings the output back to the input's level.
- **Switching** fades over 10 ms; a change of preset glides over 50 ms. A fault in the plugin gives silence, never the
  undisguised voice.

Why PSOLA and not a phase vocoder with a spectral-envelope warp: it works on the waveform, so there is no FFT per frame
(about a tenth of the arithmetic, which matters on a Raspberry Pi), a voice's attacks stay sharp (no phasiness), and pitch
and formants are separate knobs without estimating an envelope. Its weak spot is a wrong pitch estimate, which gives one
rough grain; a slight disguise tolerates that.

**Latency: 32 ms (1536 samples at 48 kHz) while on, 0 while off.** A grain needs W f of input after its mark (W its
half-width in the output) and the output is final W before the next mark, so the delay is fixed at W (1 + f) for the
widest grain. That covers voices down to about 75 Hz with "lower" and 65 Hz with "higher"; below that the grains are
narrowed (a little roughness, never a click). With the scrub's 21 ms the private microphone is 53 ms behind the room while
the disguise is on. PipeWire reads the filter's latency when the filter starts, so it keeps reporting the scrub's 21 ms
when the disguise is switched on later (checked in the isolated test): a recording's sound is then 32 ms later than the
video, which I accept rather than delaying everyone by 32 ms while the disguise is off.

## Measured (2026-11-18, synthetic voices only)

`rust/scrub/tests/disguise.rs` (`--nocapture` prints the numbers) builds sung vowels: harmonics under three formant peaks
(650, 1700, 2600 Hz) with a falling source tilt and a little breath; no recording of anyone.

| | lower | higher |
| --- | --- | --- |
| fundamental, 140 Hz steady (variation off) | 117.7 Hz, -3.00 semitones | 166.5 Hz, +3.00 semitones |
| F2 (preset x0.88 / x1.12) | x0.876 | x1.096 |
| F1 | x0.840 | x1.183 |
| level, syllables with moving pitch (variation on) | +0.04 dB | +0.08 dB |
| level, noise (unvoiced) | +0.02 dB | +0.04 dB |
| length; timing (10 ms energy envelopes) | same; within 10 ms | same; 0 ms |
| after the live scrub (vibrato voice over room noise) | -2.6 semitones | +2.5 semitones |
| a whole session with variation, 10 s in 0.5 s pieces | -3.3 to -2.5 semitones | |

- F2 and above move by the preset's ratio. F1 moves 4-6 % further than the preset: only a few harmonics define it, and the
  changed pitch samples the scaled, window-smeared envelope there differently. A property of PSOLA, measured, not hidden.
- After the live scrub the shift falls short of the preset by about half a semitone: where the scrub has re-synthesised a
  weak voice's low harmonics, the tracker sometimes cannot follow it, and those frames keep their own pitch.
- **No clicks.** The output is identical whether it is processed in PipeWire's 1024-sample blocks or in odd ones (1, 13,
  97, 256, 480, 1500, 4096), so a block boundary cannot leave a mark. Across a session that switches on, changes preset and
  switches off, the largest sample-to-sample step was 1.03x the input's own largest. Once off, the output is the input
  sample for sample.
- Two sessions seeded by the operating system differ; within a session the pitch wanders.
- The isolated end-to-end test (`packaging/privacy/isolated-test.sh`, its own PipeWire and WirePlumber, never my desktop's):
  status says off by default and the filter's control is 0; `disguise higher` sets it to 2 and a recording of the private
  microphone has the synthetic voice moved up; `disguise lower` sets 1 and moves it down; `disguise off` sets 0 and the
  voice is back at its own pitch. Run as Labyrinth OS and as LykanOS.

**CPU** (`rust/scrub/tests/cpu.rs`, release build, Intel i9-9900K, one channel at 48 kHz, PipeWire-sized blocks): the
disguise alone takes **0.7 % of one core**, the scrub and the disguise together **about 2 %**, the disguise off 0.01 %
(a copy). I have not measured it on a Raspberry Pi; by the usual ratio of a Cortex-A72 core to this one (5-8x slower) I expect
3.5-5.5 % of one Pi 4 core for the disguise and 10-17 % for both, and about half that on a Pi 5. No SIMD, no dependencies.

## Limits

- **It can be partly undone.** The method and the presets are public (this repository). Someone with the recording can
  shift it back by about three semitones and 12 % and get close to my voice; the per-session offset and the wander make
  that inexact, not impossible.
- **Only pitch and formants.** Words, accent, speaking rate, rhythm, breathing, laughter and room sound are mine as before.
- **Speaker recognition.** Models built for spoofed or shifted voices can still match me. I have not tested any model.
- **Very low voices** (below about 75 Hz with "lower") get narrower grains, slightly rough.
- **Stereo files** are disguised per channel with the same variation; each channel's pitch is tracked on its own.
- **The latency PipeWire reports** stays at the scrub's 21 ms while the disguise adds 32 ms (above).
- **Synthetic tests only.** None of the numbers come from a real voice; I will listen to it on my own microphone.

## Files

| Installed | From |
| --- | --- |
| `/usr/lib/ladspa/heimdall-scrub.so` (plugins `heimdall_scrub` and `heimdall_disguise`) | `rust/scrub-ladspa` |
| `/usr/bin/heimdall-private-mic` (`disguise on\|off\|lower\|higher`), `/usr/bin/heimdall-scrub` (`--disguise`) | `rust/scrub` |
| the filter graph, the WirePlumber settings and script | `packaging/privacy/` |
| `/usr/share/doc/heimdall-private-mic/VOICE_DISGUISE.md` | this file |

All in `heimdall-private-mic-git`, like the rest of the private microphone.

## Credits

- E. Moulines and F. Charpentier, *Pitch-synchronous waveform processing techniques for text-to-speech synthesis using
  diphones*, Speech Communication 9 (1990): TD-PSOLA.
- A. de Cheveigne and H. Kawahara, *YIN, a fundamental frequency estimator for speech and music*, JASA 111 (2002).
- storytold/realtime-voice-conversion: the idea of a live voice disguise (idea only; nothing from it is used).
