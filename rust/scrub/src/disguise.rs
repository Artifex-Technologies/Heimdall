//! Disguise my voice: a pitch shift and a formant shift with a little slow jitter, causal, for the private microphone
//! (after the scrub) and for files (`heimdall-scrub --disguise PRESET`). Off by default.
//!
//! **What it is for, honestly.** It hides casual recognition: a colleague, a stranger or a speaker-recognition model that
//! has heard my natural voice. It is light signal processing, not a voice conversion: a determined listener who knows it was
//! used can partly undo it (shift the pitch and formants back by ear or by search). Never claim more.
//!
//! **Method: TD-PSOLA with resampled grains** (time-domain pitch-synchronous overlap-add, Moulines and Charpentier, 1990; the
//! formant change by resampling each grain is the textbook extension). Written from the published method, no code copied.
//!
//! 1. A pitch tracker (YIN, de Cheveigne and Kawahara, 2002, on a copy decimated to about 12 kHz) gives the period T every
//!    5 ms, or "unvoiced".
//! 2. Analysis marks are placed one period apart in the input. Around each mark a grain is cut with a Hann window two
//!    periods wide: one glottal pulse with its formants.
//! 3. Synthesis marks are placed T / p apart in the output (p the pitch ratio), and each takes the latest analysis mark at
//!    or before it: grains are repeated (pitch up) or skipped (pitch down), so the length stays the same.
//! 4. Each grain is read at speed f (the formant ratio) before it is added: its spectrum, the formants, is scaled by f
//!    while the spacing alone sets the pitch. The sum is divided by the sum of the windows, so the level stays.
//! 5. Unvoiced sound (breath, s, f, noise) gets 5 ms grains at the same spacing in and out: no pitch change (a period
//!    imposed on noise would buzz), only the formant scaling.
//! 6. Overlapping grains are not in phase once they are resampled, so their average is up to 2 dB quieter than the
//!    input; a slow level match (0.3 s, at most -3 to +4 dB) brings the output back to the input's level.
//!
//! Why this and not a phase vocoder: it works on the waveform, so it needs no FFT per frame (about a tenth of the
//! arithmetic, which matters on a Raspberry Pi), it keeps a voice's attacks sharp (no "phasiness"), and its two knobs are
//! independent by construction. Its weak spot is a wrong pitch estimate (an octave error makes one rough grain), which a
//! slight disguise tolerates.
//!
//! **No fixed fingerprint.** Each session (each PipeWire start, each file) draws its own small offset from the preset
//! (up to 0.4 semitone and 2.5 % formant) from the operating system's randomness, and both ratios wander slowly
//! around it (a random walk with a 1.5 s memory, about 0.25 semitone and 1.5 %), so no two recordings carry the same
//! exact transformation.
//!
//! **Latency.** A grain needs input up to W f after its mark (W its half-width in the output) and output is final W
//! before the next mark, so the delay is fixed at [`LATENCY_S`] (32 ms, 1536 samples at 48 kHz). That covers voices down to
//! about 75 Hz with "lower" and 65 Hz with "higher"; below that the grains are narrowed (a little roughness, never a
//! click). Off, the input passes through sample for sample with no delay. Switching fades over 10 ms.
//!
//! Like the scrub, `process` never allocates, takes no lock and makes no system call (the real-time thread).

use crate::filters::Decimator;
use crate::rng::Rng;

/// The delay while the disguise is on, in seconds.
pub const LATENCY_S: f64 = 0.032;
const F0_MIN: f64 = 70.0;
const F0_MAX: f64 = 450.0;
/// YIN's threshold on the cumulative mean normalised difference: the first dip below it is the period. Without one, the
/// deepest dip still counts as voiced below `YIN_VOICED_MAX` (noise stays well above it).
const YIN_THRESHOLD: f32 = 0.25;
const YIN_VOICED_MAX: f32 = 0.4;
/// A voice the tracker loses for a moment (the scrub's noise in its low harmonics, a fast glide) keeps its last period this
/// long, so a syllable is not left half disguised.
const HOLD_S: f64 = 0.06;
/// A frame quieter than this (mean square, about -70 dBFS) is never voiced.
const SILENT: f32 = 1e-7;
const UNVOICED_S: f64 = 0.005;
const FADE_S: f64 = 0.010;
const GLIDE_S: f64 = 0.05;
/// The level match: energies over this long, the gain within these bounds, held in silence.
const LEVEL_S: f64 = 0.3;
const GAIN_MIN: f64 = 0.7;
const GAIN_MAX: f64 = 1.6;
const LEVEL_FLOOR: f64 = 1e-9;
/// The slow jitter: a random walk with this memory, these sizes (one standard deviation), never beyond 2.5 of them.
const JITTER_TAU_S: f64 = 1.5;
const JITTER_SEMITONES: f64 = 0.25;
const JITTER_FORMANT: f64 = 0.015;
const JITTER_CLAMP: f64 = 2.5;
/// The per-session offset from the preset: uniform within these.
const SESSION_SEMITONES: f64 = 0.4;
const SESSION_FORMANT: f64 = 0.025;
/// Parameters are updated every this many samples.
const TICK: usize = 64;

/// The presets. No free knobs: a few settled shapes are easier to choose and to test, and a free pitch knob invites the
/// one setting that is easy to undo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// Three semitones down, formants 12 % down: a deeper, larger-sounding voice.
    Lower,
    /// Three semitones up, formants 12 % up: a higher, smaller-sounding voice.
    Higher,
}

impl Preset {
    pub const ALL: [Preset; 2] = [Preset::Lower, Preset::Higher];

    pub fn name(self) -> &'static str {
        match self {
            Preset::Lower => "lower",
            Preset::Higher => "higher",
        }
    }

    pub fn parse(s: &str) -> Option<Preset> {
        Preset::ALL.into_iter().find(|p| p.name() == s)
    }

    /// The value of the LADSPA control (0 is off).
    pub fn index(self) -> u32 {
        match self {
            Preset::Lower => 1,
            Preset::Higher => 2,
        }
    }

    pub fn from_index(i: u32) -> Option<Preset> {
        Preset::ALL.into_iter().find(|p| p.index() == i)
    }

    /// The pitch shift in semitones.
    pub fn semitones(self) -> f64 {
        match self {
            Preset::Lower => -3.0,
            Preset::Higher => 3.0,
        }
    }

    /// The pitch ratio.
    pub fn pitch(self) -> f64 {
        2f64.powf(self.semitones() / 12.0)
    }

    /// The formant ratio.
    pub fn formant(self) -> f64 {
        match self {
            Preset::Lower => 0.88,
            Preset::Higher => 1.12,
        }
    }
}

/// How a disguise varies.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Fixed seed (tests, `--seed`); `None` draws one from the operating system.
    pub seed: Option<u64>,
    /// The per-session offset and the slow jitter (on in use; off only in tests that measure the preset itself).
    pub vary: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options { seed: None, vary: true }
    }
}

/// YIN on a decimated copy: the period in input samples, or unvoiced.
struct Tracker {
    dec: Decimator,
    factor: usize,
    tmin: usize,
    tmax: usize,
    /// the last 2 tmax decimated samples (a ring)
    buf: Vec<f32>,
    pos: usize,
    filled: usize,
    hop: usize,
    count: usize,
    lin: Vec<f32>,
    d: Vec<f32>,
    period: f64,
    voiced: bool,
    /// analysis frames the last period may still be held
    hold: usize,
    hold_frames: usize,
}

impl Tracker {
    fn new(sr: f64) -> Tracker {
        let factor = (sr / 12000.0).round().max(1.0) as usize;
        let r = sr / factor as f64;
        let tmin = ((r / F0_MAX).floor() as usize).max(2);
        let tmax = (r / F0_MIN).ceil() as usize + 1;
        Tracker {
            dec: Decimator::new(factor),
            factor,
            tmin,
            tmax,
            buf: vec![0.0; 2 * tmax],
            pos: 0,
            filled: 0,
            hop: ((r * 0.005).round() as usize).max(1),
            count: 0,
            lin: vec![0.0; 2 * tmax],
            d: vec![0.0; tmax + 1],
            period: 0.0,
            voiced: false,
            hold: 0,
            hold_frames: (HOLD_S / 0.005).round() as usize,
        }
    }

    fn reset(&mut self) {
        self.dec.reset();
        self.buf.iter_mut().for_each(|v| *v = 0.0);
        self.pos = 0;
        self.filled = 0;
        self.count = 0;
        self.voiced = false;
        self.hold = 0;
    }

    #[inline]
    fn push(&mut self, x: f32) {
        let Some(y) = self.dec.push(x) else { return };
        let n = self.buf.len();
        self.buf[self.pos] = y;
        self.pos = (self.pos + 1) % n;
        self.filled = (self.filled + 1).min(n);
        self.count += 1;
        if self.count >= self.hop {
            self.count = 0;
            self.analyse();
        }
    }

    fn analyse(&mut self) {
        match self.estimate() {
            Some(p) => {
                self.period = p;
                self.voiced = true;
                self.hold = self.hold_frames;
            }
            None if self.hold > 0 => self.hold -= 1,
            None => self.voiced = false,
        }
    }

    /// The period of the last 2 tmax decimated samples, in input samples, or None (unvoiced or silent).
    fn estimate(&mut self) -> Option<f64> {
        let n = self.buf.len();
        if self.filled < n {
            return None;
        }
        for i in 0..n {
            self.lin[i] = self.buf[(self.pos + i) % n];
        }
        let w = self.tmax;
        let energy = self.lin[n - w..].iter().map(|v| v * v).sum::<f32>() / w as f32;
        if energy < SILENT {
            self.hold = 0;
            return None;
        }
        // the difference function, then its cumulative mean normalised form (YIN's steps 2 and 3)
        let mut cum = 0.0f32;
        self.d[0] = 1.0;
        for tau in 1..=self.tmax {
            let (a, b) = (&self.lin[..w], &self.lin[tau..tau + w]);
            let s: f32 = a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum();
            cum += s;
            self.d[tau] = if cum > 0.0 { s * tau as f32 / cum } else { 1.0 };
        }
        // the first dip under the threshold, followed to its bottom (step 4); without one, the deepest dip if it is deep
        // enough (a voice whose pitch moves within the window, or whose low harmonics the scrub re-synthesised, has
        // shallower dips than YIN's clean examples); refined by a parabola (step 5)
        let mut tau = self.tmin;
        while tau < self.tmax && self.d[tau] >= YIN_THRESHOLD {
            tau += 1;
        }
        if tau >= self.tmax {
            tau = (self.tmin..self.tmax).min_by(|&a, &b| self.d[a].total_cmp(&self.d[b])).unwrap_or(self.tmin);
            if self.d[tau] >= YIN_VOICED_MAX {
                return None;
            }
        }
        while tau + 1 < self.tmax && self.d[tau + 1] < self.d[tau] {
            tau += 1;
        }
        let (a, b, c) = (self.d[tau - 1] as f64, self.d[tau] as f64, self.d[tau + 1] as f64);
        let den = a - 2.0 * b + c;
        let shift = if den > 0.0 { (0.5 * (a - c) / den).clamp(-0.5, 0.5) } else { 0.0 };
        Some((tau as f64 + shift) * self.factor as f64)
    }
}

/// One channel of the voice disguise. `process` never allocates.
pub struct Disguise {
    lat: usize,
    mask: usize,
    /// the input, always kept (also while off), so switching on starts from the recent past
    ring: Vec<f32>,
    acc: Vec<f32>,
    wsum: Vec<f32>,
    /// samples received
    n: i64,
    /// the last output position handed out while running
    emitted: i64,
    running: bool,
    s_next: f64,
    a: f64,
    tracker: Tracker,
    preset: Option<Preset>,
    /// the preset being faded out after `off`
    shape: Preset,
    mix: f64,
    fade_step: f64,
    instant: bool,
    vary: bool,
    rng: Rng,
    off_st: f64,
    off_f: f64,
    jit: [f64; 2],
    jit_a: f64,
    jit_b: f64,
    glide: f64,
    p_cur: f64,
    f_cur: f64,
    tick: usize,
    unvoiced_t: f64,
    e_in: f64,
    e_out: f64,
    level_a: f64,
    gain: f64,
    gain_target: f64,
}

impl Disguise {
    /// Off until [`Disguise::set_preset`]; the session's variation is drawn now.
    pub fn new(sr: f64, opts: Options) -> Disguise {
        let lat = ((LATENCY_S * sr).round() as usize).max(64);
        let cap = (4 * lat).next_power_of_two();
        let mut rng = Rng::new(opts.seed);
        let (off_st, off_f) = if opts.vary {
            ((2.0 * rng.uniform() - 1.0) * SESSION_SEMITONES, (2.0 * rng.uniform() - 1.0) * SESSION_FORMANT)
        } else {
            (0.0, 0.0)
        };
        let dt = TICK as f64 / sr;
        let jit_a = (-dt / JITTER_TAU_S).exp();
        Disguise {
            lat,
            mask: cap - 1,
            ring: vec![0.0; cap],
            acc: vec![0.0; cap],
            wsum: vec![0.0; cap],
            n: 0,
            emitted: -1,
            running: false,
            s_next: 0.0,
            a: 0.0,
            tracker: Tracker::new(sr),
            preset: None,
            shape: Preset::Lower,
            mix: 0.0,
            fade_step: 1.0 / (FADE_S * sr).max(1.0),
            instant: false,
            vary: opts.vary,
            rng,
            off_st,
            off_f,
            jit: [0.0; 2],
            jit_a,
            jit_b: (1.0 - jit_a * jit_a).sqrt(),
            glide: 1.0 - (-dt / GLIDE_S).exp(),
            p_cur: 1.0,
            f_cur: 1.0,
            tick: 0,
            unvoiced_t: (UNVOICED_S * sr).max(4.0),
            e_in: 0.0,
            e_out: 0.0,
            level_a: (-1.0 / (LEVEL_S * sr)).exp(),
            gain: 1.0,
            gain_target: 1.0,
        }
    }

    /// Switch to a preset, or off (`None`). Fades over 10 ms; a change between presets glides.
    pub fn set_preset(&mut self, p: Option<Preset>) {
        self.preset = p;
    }

    /// The same at once, without the fade (a file starts disguised from its first sample).
    pub fn set_preset_now(&mut self, p: Option<Preset>) {
        self.preset = p;
        self.instant = true;
    }

    pub fn preset(&self) -> Option<Preset> {
        self.preset
    }

    /// Samples of delay between input and output: [`LATENCY_S`] while on (or fading), 0 while off.
    pub fn latency(&self) -> usize {
        if self.running || self.preset.is_some() {
            self.lat
        } else {
            0
        }
    }

    /// The fixed delay while on.
    pub fn on_latency(&self) -> usize {
        self.lat
    }

    fn targets(&self) -> (f64, f64) {
        let st = self.shape.semitones() + self.off_st + JITTER_SEMITONES * self.jit[0];
        let f = self.shape.formant() * (1.0 + self.off_f + JITTER_FORMANT * self.jit[1]);
        (2f64.powf(st / 12.0), f)
    }

    fn update_params(&mut self) {
        if self.vary {
            for j in self.jit.iter_mut() {
                *j = (self.jit_a * *j + self.jit_b * self.rng.normal() as f64).clamp(-JITTER_CLAMP, JITTER_CLAMP);
            }
        }
        let (p, f) = self.targets();
        self.p_cur += (p - self.p_cur) * self.glide;
        self.f_cur += (f - self.f_cur) * self.glide;
        if self.e_in > LEVEL_FLOOR && self.e_out > LEVEL_FLOOR * 1e-3 {
            self.gain_target = (self.e_in / self.e_out).sqrt().clamp(GAIN_MIN, GAIN_MAX);
        }
        self.gain += (self.gain_target - self.gain) * self.glide;
    }

    /// Start from the input already kept: grains from one latency back, so the very next output is complete.
    fn start(&mut self) {
        self.acc.iter_mut().for_each(|v| *v = 0.0);
        self.wsum.iter_mut().for_each(|v| *v = 0.0);
        let t = self.n - 1 - self.lat as i64;
        self.emitted = t - 1;
        self.s_next = (t - self.lat as i64) as f64;
        self.a = self.s_next;
        (self.p_cur, self.f_cur) = self.targets();
        (self.e_in, self.e_out, self.gain, self.gain_target) = (0.0, 0.0, 1.0, 1.0);
        // prime the pitch tracker with the recent past
        self.tracker.reset();
        let back = (2 * self.tracker.tmax * self.tracker.factor + 64) as i64;
        for i in (self.n - back).max(0)..self.n {
            self.tracker.push(self.ring[(i as usize) & self.mask]);
        }
        self.running = true;
    }

    /// Catmull-Rom interpolation of the kept input at a fractional position (0 outside what was kept).
    #[inline]
    fn at(&self, pos: f64) -> f32 {
        let i = pos.floor();
        let t = (pos - i) as f32;
        let i = i as i64;
        let get = |k: i64| if k >= 0 && k < self.n && self.n - k <= self.mask as i64 { self.ring[(k as usize) & self.mask] } else { 0.0 };
        let (y0, y1, y2, y3) = (get(i - 1), get(i), get(i + 1), get(i + 2));
        y1 + 0.5 * t * (y2 - y0 + t * (2.0 * y0 - 5.0 * y1 + 4.0 * y2 - y3 + t * (3.0 * (y1 - y2) + y3 - y0)))
    }

    /// One grain: the input around `a`, read at speed `f`, Hann-windowed over `s` +- `w` in the output.
    fn add_grain(&mut self, s: f64, a: f64, w: f64, f: f64) {
        let lo = ((s - w).floor() as i64 + 1).max(self.emitted + 1);
        let hi = (s + w).ceil() as i64 - 1;
        if hi < lo {
            return;
        }
        let k = std::f64::consts::PI / w;
        let (mut sn, mut c) = (k * (lo as f64 - s)).sin_cos();
        let (sd, cd) = k.sin_cos();
        for pos in lo..=hi {
            let u = pos as f64 - s;
            let win = 0.5 * (1.0 + c);
            let v = self.at(a + u * f);
            let idx = (pos as usize) & self.mask;
            self.acc[idx] += (win * v as f64) as f32;
            self.wsum[idx] += win as f32;
            (sn, c) = (sn * cd + c * sd, c * cd - sn * sd);
        }
    }

    /// Every grain whose input is all here.
    fn make_grains(&mut self) {
        let last = (self.n - 1) as f64;
        loop {
            let (ta, p) = if self.tracker.voiced { (self.tracker.period, self.p_cur) } else { (self.unvoiced_t, 1.0) };
            let f = self.f_cur;
            let ts = ta / p;
            // a grain must be complete before the output reaches it: W (1 + f) within the latency
            let wcap = (self.lat as f64 - 8.0) / (1.0 + f);
            let w = (ta / f).max(ts).min(wcap);
            if self.s_next + w * f + 3.0 > last {
                break;
            }
            while self.a + ta <= self.s_next {
                self.a += ta;
            }
            self.add_grain(self.s_next, self.a, w, f);
            self.s_next += ts;
        }
    }

    /// Disguise `input` into `output` (same length; any block size; the result does not depend on the block sizes).
    pub fn process(&mut self, input: &[f32], output: &mut [f32]) {
        debug_assert_eq!(input.len(), output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            let x = if x.is_finite() { *x } else { 0.0 };
            self.ring[(self.n as usize) & self.mask] = x;
            self.n += 1;
            if let Some(p) = self.preset {
                self.shape = p;
                if !self.running {
                    self.start();
                }
                if self.instant {
                    self.mix = 1.0;
                }
            } else if self.instant {
                self.mix = 0.0;
            }
            self.instant = false;
            if !self.running {
                *y = x;
                continue;
            }
            self.tracker.push(x);
            self.tick += 1;
            if self.tick >= TICK {
                self.tick = 0;
                self.update_params();
            }
            self.make_grains();
            let t = self.n - 1 - self.lat as i64;
            let wet = if t >= 0 {
                let i = (t as usize) & self.mask;
                let v = self.acc[i] / self.wsum[i].max(0.5);
                self.acc[i] = 0.0;
                self.wsum[i] = 0.0;
                // the level match compares the output with the input it came from (same position)
                let la = self.level_a;
                self.e_in = la * self.e_in + (1.0 - la) * (self.ring[i] as f64).powi(2);
                self.e_out = la * self.e_out + (1.0 - la) * (v as f64).powi(2);
                (v as f64 * self.gain) as f32
            } else {
                0.0
            };
            self.emitted = t;
            let target = if self.preset.is_some() { 1.0 } else { 0.0 };
            if self.mix < target {
                self.mix = (self.mix + self.fade_step).min(1.0);
            } else if self.mix > target {
                self.mix = (self.mix - self.fade_step).max(0.0);
            }
            if self.mix >= 1.0 {
                *y = wet;
            } else {
                let g = (0.5 - 0.5 * (std::f64::consts::PI * self.mix).cos()) as f32;
                *y = x + g * (wet - x);
            }
            if self.mix <= 0.0 && self.preset.is_none() {
                self.running = false;
            }
        }
    }
}

/// A whole signal disguised from its first sample, delay removed: same length, same timing.
pub fn disguise_buffer(x: &[f32], sr: f64, preset: Preset, opts: Options) -> Vec<f32> {
    let mut d = Disguise::new(sr, opts);
    d.set_preset_now(Some(preset));
    let lat = d.on_latency();
    let mut padded = x.to_vec();
    padded.resize(x.len() + lat, 0.0);
    let mut y = vec![0.0; padded.len()];
    for (i, o) in padded.chunks(1024).zip(y.chunks_mut(1024)) {
        d.process(i, o);
    }
    y.drain(..lat);
    y
}

/// The file tool's stage after the scrub: streamed, delay removed (`push` as audio arrives, `finish` at the end).
pub struct FileStage {
    d: Disguise,
    skip: usize,
    tmp: Vec<f32>,
}

impl FileStage {
    pub fn new(sr: f64, preset: Preset, opts: Options) -> FileStage {
        let mut d = Disguise::new(sr, opts);
        d.set_preset_now(Some(preset));
        let skip = d.on_latency();
        FileStage { d, skip, tmp: Vec::new() }
    }

    pub fn push(&mut self, x: &[f32], out: &mut Vec<f32>) {
        self.tmp.resize(x.len(), 0.0);
        self.d.process(x, &mut self.tmp);
        let s = self.skip.min(self.tmp.len());
        self.skip -= s;
        out.extend_from_slice(&self.tmp[s..]);
    }

    pub fn finish(&mut self, out: &mut Vec<f32>) {
        // the delay's worth of silence pushes the last input sample out: as many samples out as went in
        let zeros = vec![0.0; self.d.on_latency()];
        self.push(&zeros, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_parse_and_index() {
        for p in Preset::ALL {
            assert_eq!(Preset::parse(p.name()), Some(p));
            assert_eq!(Preset::from_index(p.index()), Some(p));
        }
        assert_eq!(Preset::parse("off"), None);
        assert_eq!(Preset::from_index(0), None);
        assert!((Preset::Lower.pitch() - 0.8409).abs() < 1e-3);
    }

    #[test]
    fn off_is_the_input_sample_for_sample() {
        let mut d = Disguise::new(48000.0, Options { seed: Some(1), vary: true });
        let x: Vec<f32> = (0..20000).map(|i| ((i * 7919) % 1000) as f32 / 1000.0 - 0.5).collect();
        let mut y = vec![0.0; x.len()];
        d.process(&x, &mut y);
        assert_eq!(x, y);
        assert_eq!(d.latency(), 0);
    }

    #[test]
    fn noise_is_not_voiced() {
        let mut t = Tracker::new(48000.0);
        let mut rng = Rng::seeded(5);
        let mut voiced = 0;
        for i in 0..96000 {
            t.push(0.05 * rng.normal());
            voiced += (i % 240 == 0 && t.voiced) as usize;
        }
        assert!(voiced <= 4, "{voiced} of 400 frames");
    }

    #[test]
    fn the_tracker_finds_a_period() {
        let sr = 48000.0;
        let mut t = Tracker::new(sr);
        for i in 0..24000 {
            let ph = 2.0 * std::f64::consts::PI * 150.0 * i as f64 / sr;
            t.push((0.3 * (ph.sin() + 0.5 * (2.0 * ph).sin() + 0.3 * (3.0 * ph).sin())) as f32);
        }
        assert!(t.voiced);
        assert!((t.period - sr / 150.0).abs() < 1.0, "{}", t.period);
    }
}
