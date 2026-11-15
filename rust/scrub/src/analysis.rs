//! The slow, causal look at the past: the signal decimated to about 8 kHz, a 0.25 s spectrum every 64 ms with its noise
//! floor, the mains-hum tracker and (live) the ridge tracker. Only past samples are used, so the live filter can act on what
//! it learns at once. Nothing here allocates after `new`.

use crate::complex::C32;
use crate::config::Config;
use crate::fft::{hann, nearest_pow2, RealFft};
use crate::filters::Decimator;

const LN2: f32 = std::f32::consts::LN_2;

/// One complex heterodyne: mixes a harmonic down to 0 Hz and low-passes it (two one-pole stages, about 2 Hz).
#[derive(Clone, Copy, Default)]
struct Het {
    rot: (f64, f64),
    osc: (f64, f64),
    lp1: (f64, f64),
    lp2: (f64, f64),
}

impl Het {
    fn new(f_hz: f64, fa: f64) -> Het {
        let w = -2.0 * std::f64::consts::PI * f_hz / fa;
        Het { rot: (w.cos(), w.sin()), osc: (1.0, 0.0), ..Het::default() }
    }

    #[inline]
    fn push(&mut self, x: f64, a: f64) {
        let (c, s) = self.osc;
        let (rc, rs) = self.rot;
        self.osc = (c * rc - s * rs, c * rs + s * rc);
        let m = (x * c, x * s);
        self.lp1 = (a * self.lp1.0 + (1.0 - a) * m.0, a * self.lp1.1 + (1.0 - a) * m.1);
        self.lp2 = (a * self.lp2.0 + (1.0 - a) * self.lp1.0, a * self.lp2.1 + (1.0 - a) * self.lp1.1);
    }

    fn renormalise(&mut self) {
        let (c, s) = self.osc;
        let n = (c * c + s * s).sqrt();
        self.osc = (c / n, s / n);
    }
}

const HARMS: usize = 4;

/// The mains frequency, tracked: the grid wanders a few hundredths of a hertz around 50 or 60 Hz (that wander is the ENF
/// that dates a recording), and the notches must follow it, harmonic k by k times the wander.
pub struct HumTracker {
    fa: f64,
    a: f64,
    every: usize,
    count: usize,
    rate: f64,
    /// per nominal (50, 60) and harmonic: the line and a reference 6.5 Hz above it
    line: [[Het; HARMS]; 2],
    refr: [[Het; HARMS]; 2],
    prev: [[(f64, f64); HARMS]; 2],
    pw_line: [[f64; HARMS]; 2],
    pw_ref: [[f64; HARMS]; 2],
    delta: [[f64; HARMS]; 2],
    grid: [f64; 2],
    /// seconds of hangover left in which the hum counts as present
    present: [f64; 2],
    samples: u64,
}

pub const NOMINALS: [f64; 2] = [50.0, 60.0];

impl HumTracker {
    pub fn new(fa: f64) -> HumTracker {
        let mut line = [[Het::default(); HARMS]; 2];
        let mut refr = [[Het::default(); HARMS]; 2];
        for (i, n) in NOMINALS.iter().enumerate() {
            for k in 0..HARMS {
                let f = n * (k + 1) as f64;
                line[i][k] = Het::new(f, fa);
                refr[i][k] = Het::new(f + 6.5, fa);
            }
        }
        let every = (fa / 100.0).round().max(1.0) as usize;
        HumTracker {
            fa,
            a: (-2.0 * std::f64::consts::PI * 2.0 / fa).exp(),
            every,
            count: 0,
            rate: fa / every as f64,
            line,
            refr,
            prev: [[(0.0, 0.0); HARMS]; 2],
            pw_line: [[0.0; HARMS]; 2],
            pw_ref: [[0.0; HARMS]; 2],
            delta: [[0.0; HARMS]; 2],
            grid: NOMINALS,
            present: [0.0; 2],
            samples: 0,
        }
    }

    /// One decimated sample.
    pub fn push(&mut self, x: f32) {
        let x = x as f64;
        for i in 0..2 {
            for k in 0..HARMS {
                self.line[i][k].push(x, self.a);
                self.refr[i][k].push(x, self.a);
            }
        }
        self.samples += 1;
        self.count += 1;
        if self.count < self.every {
            return;
        }
        self.count = 0;
        let dt = 1.0 / self.rate;
        let ema = (-dt / 1.0f64).exp();
        let warm = self.samples as f64 / self.fa > 1.0;
        for i in 0..2 {
            let (mut wsum, mut gsum) = (0.0, 0.0);
            for k in 0..HARMS {
                let z = self.line[i][k].lp2;
                let r = self.refr[i][k].lp2;
                let p = self.prev[i][k];
                self.prev[i][k] = z;
                // phase step since the last look: the line's offset from k times nominal
                let cross = (z.0 * p.0 + z.1 * p.1, z.1 * p.0 - z.0 * p.1);
                let d = cross.1.atan2(cross.0) * self.rate / (2.0 * std::f64::consts::PI);
                self.pw_line[i][k] = ema * self.pw_line[i][k] + (1.0 - ema) * (z.0 * z.0 + z.1 * z.1);
                self.pw_ref[i][k] = ema * self.pw_ref[i][k] + (1.0 - ema) * (r.0 * r.0 + r.1 * r.1);
                if d.is_finite() && d.abs() < 1.0 {
                    self.delta[i][k] = ema * self.delta[i][k] + (1.0 - ema) * d;
                }
                if warm && self.pw_line[i][k] > 4.0 * self.pw_ref[i][k] && self.pw_line[i][k] > 1e-14 {
                    let k1 = (k + 1) as f64;
                    let g = NOMINALS[i] + (self.delta[i][k] / k1).clamp(-0.2, 0.2);
                    wsum += self.pw_line[i][k];
                    gsum += self.pw_line[i][k] * g;
                }
            }
            if wsum > 0.0 {
                self.grid[i] = gsum / wsum;
                self.present[i] = 5.0;
            } else {
                // no line: drift back to nominal over about ten seconds
                self.grid[i] += (NOMINALS[i] - self.grid[i]) * (dt / 10.0);
                self.present[i] = (self.present[i] - dt).max(0.0);
            }
        }
        if self.samples % (self.every as u64 * 100) == 0 {
            for row in self.line.iter_mut().chain(self.refr.iter_mut()) {
                row.iter_mut().for_each(Het::renormalise);
            }
        }
    }

    /// The tracked grid frequency for nominal 50 (`0`) or 60 (`1`).
    pub fn grid_hz(&self, i: usize) -> f64 {
        self.grid[i]
    }

    /// Whether hum of that grid was seen in the last few seconds.
    pub fn present(&self, i: usize) -> bool {
        self.present[i] > 0.0
    }
}

/// A followed narrowband line in the slow spectrum.
#[derive(Clone, Copy, Default)]
pub struct Track {
    pub f: f32,
    pub slope: f32,
    pub age: u32,
    pub missed: u32,
    pub f_min: f32,
    pub f_max: f32,
    pub strength: f32,
    pub confirmed: bool,
    used: bool,
}

pub const MAX_TRACKS: usize = 96;

/// Follows lines frame by frame from the past only: a line that lasts `ridge_min_s` and glides no faster than an aircraft
/// becomes a confirmed ridge, removed from then on while it lasts. Tracking starts at `ridge_db` (4 dB), far below what the
/// fast stage keeps as foreground, so a flyover that fades in is usually confirmed long before it is loud enough to pass.
pub struct RidgeTracker {
    pub tracks: [Track; MAX_TRACKS],
    min_frames: u32,
    max_step_hz: f32,
    df: f32,
    dt: f32,
    slope_max: f32,
    keep_stationary: bool,
    drift: f32,
    pub confirmed_total: usize,
}

impl RidgeTracker {
    fn new(cfg: &Config, df: f32, dt: f32) -> RidgeTracker {
        let max_bins = (cfg.ridge_max_slope_hz_s * dt / df).ceil().max(1.0);
        RidgeTracker {
            tracks: [Track::default(); MAX_TRACKS],
            min_frames: (cfg.ridge_min_s / dt).ceil() as u32,
            max_step_hz: max_bins * df + 0.5 * df,
            df,
            dt,
            slope_max: cfg.ridge_max_slope_hz_s,
            keep_stationary: cfg.keep_hum,
            drift: cfg.stationary_max_drift_hz,
            confirmed_total: 0,
        }
    }

    /// One frame's peaks: (frequency in Hz, height above the floor in dB), at most `peaks.len()`.
    fn step(&mut self, peaks: &mut [(f32, f32, bool)]) {
        // strongest tracks choose first
        let mut order = [0usize; MAX_TRACKS];
        let mut n = 0;
        for (i, t) in self.tracks.iter().enumerate() {
            if t.used {
                order[n] = i;
                n += 1;
            }
        }
        order[..n].sort_unstable_by(|&a, &b| self.tracks[b].strength.total_cmp(&self.tracks[a].strength));
        for &i in &order[..n] {
            let t = &mut self.tracks[i];
            let pred = t.f + t.slope;
            let mut best: Option<usize> = None;
            for (j, p) in peaks.iter().enumerate() {
                if !p.2 && (p.0 - pred).abs() <= self.max_step_hz && best.is_none_or(|b| (p.0 - pred).abs() < (peaks[b].0 - pred).abs()) {
                    best = Some(j);
                }
            }
            match best {
                Some(j) => {
                    peaks[j].2 = true;
                    let (f, db) = (peaks[j].0, peaks[j].1);
                    t.slope = if t.age == 0 { 0.0 } else { 0.7 * t.slope + 0.3 * (f - t.f) };
                    t.f = f;
                    t.age += 1;
                    t.missed = 0;
                    t.f_min = t.f_min.min(f);
                    t.f_max = t.f_max.max(f);
                    t.strength = 0.8 * t.strength + 0.2 * db;
                }
                None => {
                    t.missed += 1;
                    t.f += t.slope;
                    // a one-frame gap is bridged (as the reference's closing does); a confirmed ridge is held a little
                    // longer so a dip under 4 dB does not open a leak while it is still there
                    let limit = if t.confirmed { 4 } else { 1 };
                    if t.missed > limit {
                        t.used = false;
                        t.confirmed = false;
                    }
                }
            }
            if t.used && !t.confirmed && t.missed == 0 && t.age >= self.min_frames {
                let extent = t.f_max - t.f_min;
                let broad = extent > self.slope_max * t.age as f32 * self.dt + 6.0 * self.df;
                let steady = self.keep_stationary && extent <= self.drift + 2.0 * self.df;
                if !broad && !steady {
                    t.confirmed = true;
                    self.confirmed_total += 1;
                }
            }
        }
        for p in peaks.iter() {
            if p.2 {
                continue;
            }
            if let Some(slot) = self.tracks.iter_mut().find(|t| !t.used) {
                *slot = Track { f: p.0, f_min: p.0, f_max: p.0, strength: p.1, used: true, ..Track::default() };
            } else {
                break;
            }
        }
    }
}

/// The slow analysis shared by both modes.
pub struct FineAnalyzer {
    dec: Decimator,
    pub fa: f64,
    na: usize,
    hop: usize,
    fft: RealFft,
    win: Vec<f32>,
    win_sq: f32,
    ring: Vec<f32>,
    pos: usize,
    since: usize,
    filled: usize,
    frame: Vec<f32>,
    bins: Vec<C32>,
    /// bins kept: 0..nk (the band plus room for the floor's median)
    nk: usize,
    pub df: f32,
    k_lo: usize,
    k_hi: usize,
    nf: usize,
    logm: Vec<f32>,
    med: Vec<f32>,
    scratch: Vec<f32>,
    floor_log: Vec<f32>,
    floor_alpha: f32,
    pub floor: Vec<f32>,
    pub frames: u64,
    pub hum: HumTracker,
    pub ridges: Option<RidgeTracker>,
    ridge_db: f32,
    peaks: Vec<(f32, f32, bool)>,
}

impl FineAnalyzer {
    /// `track_ridges`: live mode follows ridges here; the whole-file mode finds them with lookahead instead.
    pub fn new(cfg: &Config, sr: f64, track_ridges: bool) -> FineAnalyzer {
        let factor = (sr / 8000.0).round().max(1.0) as usize;
        let fa = sr / factor as f64;
        let na = nearest_pow2(cfg.window_s as f64 * fa);
        let hop = na / 4;
        let df = (fa / na as f64) as f32;
        let nf = (((cfg.floor_freq_hz / df).round() as usize) | 1).max(3);
        let k_lo = (cfg.band.0 / df).ceil().max(1.0) as usize;
        let k_hi = ((cfg.band.1 / df).floor() as usize).min(na / 2 - 1);
        let nk = (k_hi + nf / 2 + 2).min(na / 2 + 1);
        let win = hann(na);
        let win_sq = win.iter().map(|w| w * w).sum();
        let dt = hop as f32 / fa as f32;
        FineAnalyzer {
            dec: Decimator::new(factor),
            fa,
            na,
            hop,
            fft: RealFft::new(na),
            win,
            win_sq,
            ring: vec![0.0; na],
            pos: 0,
            since: 0,
            filled: 0,
            frame: vec![0.0; na],
            bins: vec![C32::ZERO; na / 2 + 1],
            nk,
            df,
            k_lo,
            k_hi,
            nf,
            logm: vec![0.0; nk],
            med: vec![0.0; nk],
            scratch: vec![0.0; nf],
            floor_log: vec![0.0; nk],
            floor_alpha: (-dt / (cfg.floor_time_s / 2.0)).exp(),
            floor: vec![0.0; nk],
            frames: 0,
            hum: HumTracker::new(fa),
            ridges: track_ridges.then(|| RidgeTracker::new(cfg, df, dt)),
            ridge_db: cfg.ridge_db,
            peaks: Vec::with_capacity(nk),
        }
    }

    /// Seconds between two analyses.
    pub fn frame_seconds(&self) -> f64 {
        self.hop as f64 / self.fa
    }

    /// One input sample (at the full rate). Returns true when a new frame was analysed.
    #[inline]
    pub fn push(&mut self, x: f32) -> bool {
        let Some(y) = self.dec.push(x) else { return false };
        self.hum.push(y);
        self.ring[self.pos] = y;
        self.pos = (self.pos + 1) % self.na;
        self.filled = (self.filled + 1).min(self.na);
        self.since += 1;
        if self.since < self.hop || self.filled < self.na {
            return false;
        }
        self.since = 0;
        self.analyse();
        true
    }

    fn analyse(&mut self) {
        for i in 0..self.na {
            self.frame[i] = self.ring[(self.pos + i) % self.na] * self.win[i];
        }
        self.fft.forward(&self.frame, &mut self.bins);
        for k in 0..self.nk {
            self.logm[k] = (self.bins[k].abs() + 1e-12).ln();
        }
        // median across frequency (nearest edges), then smoothed over time
        let h = self.nf / 2;
        for k in 0..self.nk {
            for (j, s) in self.scratch.iter_mut().enumerate() {
                *s = self.logm[(k + j).saturating_sub(h).min(self.nk - 1)];
            }
            let (_, m, _) = self.scratch.select_nth_unstable_by(h, |a, b| a.total_cmp(b));
            self.med[k] = *m;
        }
        let a = if self.frames == 0 { 0.0 } else { self.floor_alpha };
        for k in 0..self.nk {
            self.floor_log[k] = a * self.floor_log[k] + (1.0 - a) * self.med[k];
            self.floor[k] = self.floor_log[k].exp();
        }
        self.frames += 1;
        if let Some(tr) = self.ridges.as_mut() {
            self.peaks.clear();
            for k in self.k_lo..=self.k_hi {
                let r = 20.0 / std::f32::consts::LN_10 * (self.logm[k] - self.floor_log[k]);
                let left = self.logm[k - 1] - self.floor_log[k - 1];
                let right = self.logm[k + 1] - self.floor_log[k + 1];
                let here = self.logm[k] - self.floor_log[k];
                if r > self.ridge_db && here >= left && here >= right {
                    // parabolic interpolation on the log magnitude for a sub-bin frequency
                    let (y0, y1, y2) = (self.logm[k - 1], self.logm[k], self.logm[k + 1]);
                    let den = y0 - 2.0 * y1 + y2;
                    let d = if den.abs() > 1e-9 { (0.5 * (y0 - y2) / den).clamp(-0.5, 0.5) } else { 0.0 };
                    self.peaks.push(((k as f32 + d) * self.df, r, false));
                }
            }
            tr.step(&mut self.peaks);
        }
    }

    /// How far the strongest of the three bins around `f_hz` stands above the floor, dB (-99 before the first frame).
    pub fn level_db_at(&self, f_hz: f64) -> f32 {
        if self.frames == 0 {
            return -99.0;
        }
        let k = (f_hz as f32 / self.df).round() as usize;
        let lo = k.saturating_sub(1);
        let hi = (k + 1).min(self.nk - 1);
        (lo..=hi).map(|j| self.logm[j] - self.floor_log[j]).fold(f32::NEG_INFINITY, f32::max) * (20.0 / std::f32::consts::LN_10)
    }

    /// The standard deviation of white noise at `sr` whose level matches the floor at `f_hz`: what fills a removed band.
    pub fn noise_sd_at(&self, f_hz: f64, sr: f64) -> f64 {
        if self.frames == 0 {
            return 0.0;
        }
        let k = ((f_hz as f32 / self.df).round() as usize).min(self.nk - 1);
        let fl = self.floor[k];
        // median |X| of Gaussian noise = sqrt(ln 2 * E|X|^2), and E|X|^2 = variance * sum(w^2)
        let var_a = (fl * fl) / (LN2 * self.win_sq);
        (var_a as f64 * sr / self.fa).sqrt()
    }
}
