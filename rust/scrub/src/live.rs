//! The live scrub: causal, about 21 ms of added latency at 48 kHz, for the private microphone.
//!
//! The whole-file scrub decides with lookahead on a 0.25 s spectrum; a call cannot wait a quarter of a second. So the live
//! one splits the work:
//!
//! 1. **The slow look at the past** (`analysis`): every 64 ms a 0.25 s spectrum of the last quarter second, its noise floor,
//!    the mains frequency and the lines in it. A line that has lasted `ridge_min_s` and glides like an aircraft is a ridge.
//! 2. **Notches** (`stage`): every mains harmonic, and each ridge while it lasts, is removed by a narrow notch and refilled
//!    with noise at the floor's level. Zero latency: they act on the current sample with what the past taught.
//! 3. **A short spectrum** (here): 1024-point frames (21 ms, 47 Hz bins) every 256 samples. In the protected band every bin
//!    less than `foreground_db` above the floor is replaced by fresh random-phase noise at the floor's power, so a line under
//!    the noise (the one a matched filter digs out) is gone; louder bins (speech) pass untouched. The floor is the minimum of
//!    the smoothed power over the last 1.5 s (minimum statistics), the median of five neighbouring bins, so speech does not
//!    lift it and a line inside a bin cannot set it.
//!
//! Above the band nothing changes but a delay: unmodified bins reconstruct exactly.

use crate::complex::C32;
use crate::config::{Config, Report};
use crate::fft::{hann, nearest_pow2, RealFft};
use crate::rng::Rng;
use crate::stage::TimeStage;

const SUBWINDOWS: usize = 6;

/// One channel of the live scrub. `process` never allocates.
pub struct Live {
    n: usize,
    h: usize,
    fft: RealFft,
    win: Vec<f32>,
    stage: TimeStage,
    /// the last n samples after the notches, and as they came (outside the band the output is built from the raw ones:
    /// the notches' phase reaches a little above the band)
    frame: Vec<f32>,
    frame_raw: Vec<f32>,
    fill: usize,
    tmp: Vec<f32>,
    bins: Vec<C32>,
    bins_raw: Vec<C32>,
    ola: Vec<f32>,
    outq: Vec<f32>,
    q_read: usize,
    q_len: usize,
    k_lo: usize,
    k_hi: usize,
    kmax: usize,
    alpha: f32,
    ps: Vec<f32>,
    sub_min: Vec<f32>,
    mins: Vec<[f32; SUBWINDOWS]>,
    sub_len: usize,
    sub_count: usize,
    sub_idx: usize,
    pmin: Vec<f32>,
    floor: Vec<f32>,
    bias: f32,
    fg: f32,
    rng: Rng,
    in_band: u64,
    replaced: u64,
}

impl Live {
    pub fn new(cfg: &Config, sr: f64) -> Live {
        let n = nearest_pow2(0.0213 * sr).max(64);
        let h = n / 4;
        let df = sr / n as f64;
        let k_lo = ((cfg.band.0 as f64 / df).ceil() as usize).max(1);
        let k_hi = ((cfg.band.1 as f64 / df).floor() as usize).min(n / 2 - 3);
        let kmax = k_hi + 2;
        let frame_s = h as f64 / sr;
        let sub_len = ((1.5 / frame_s) / SUBWINDOWS as f64).ceil().max(1.0) as usize;
        let mut rng = Rng::new(cfg.seed);
        let stage_rng = Rng::seeded(rng.next_u64());
        let mut live = Live {
            n,
            h,
            fft: RealFft::new(n),
            win: hann(n),
            stage: TimeStage::new(cfg, sr, true, stage_rng),
            frame: vec![0.0; n],
            frame_raw: vec![0.0; n],
            fill: 0,
            tmp: vec![0.0; n],
            bins: vec![C32::ZERO; n / 2 + 1],
            bins_raw: vec![C32::ZERO; n / 2 + 1],
            ola: vec![0.0; n],
            outq: vec![0.0; 2 * n],
            q_read: 0,
            // fixed latency: a hop's worth of silence ahead of the first frame's output
            q_len: h,
            k_lo,
            k_hi,
            kmax,
            alpha: (-frame_s / 0.04).exp() as f32,
            ps: vec![0.0; kmax + 1],
            sub_min: vec![f32::INFINITY; kmax + 1],
            mins: vec![[f32::INFINITY; SUBWINDOWS]; kmax + 1],
            sub_len,
            sub_count: 0,
            sub_idx: 0,
            pmin: vec![0.0; kmax + 1],
            floor: vec![0.0; kmax + 1],
            bias: 1.0,
            fg: 10f32.powf(cfg.foreground_db / 10.0),
            rng,
            in_band: 0,
            replaced: 0,
        };
        live.bias = live.calibrate();
        live.reset_floor();
        live
    }

    /// Samples of delay between input and output.
    pub fn latency(&self) -> usize {
        self.n
    }

    /// The minimum of smoothed power underestimates the mean noise power by a factor that depends on the window, the
    /// smoothing and the frame overlap; measure it once on white noise through this very STFT.
    fn calibrate(&mut self) -> f32 {
        let mut rng = Rng::seeded(7);
        let frames = 6 * self.sub_len * SUBWINDOWS;
        let warm = 2 * self.sub_len * SUBWINDOWS;
        let mut buf = vec![0.0f32; self.n];
        let (mut sum_p, mut sum_floor) = (0.0f64, 0.0f64);
        for f in 0..frames {
            buf.copy_within(self.h.., 0);
            for v in buf[self.n - self.h..].iter_mut() {
                *v = rng.normal();
            }
            for i in 0..self.n {
                self.tmp[i] = buf[i] * self.win[i];
            }
            self.fft.forward(&self.tmp, &mut self.bins);
            self.update_floor(1.0);
            if f >= warm {
                for k in self.k_lo..=self.k_hi {
                    sum_p += self.bins[k].norm_sqr() as f64;
                    sum_floor += self.floor[k] as f64;
                }
            }
        }
        if sum_floor > 0.0 {
            (sum_p / sum_floor) as f32
        } else {
            1.0
        }
    }

    fn reset_floor(&mut self) {
        self.ps.iter_mut().for_each(|v| *v = 0.0);
        self.sub_min.iter_mut().for_each(|v| *v = f32::INFINITY);
        self.mins.iter_mut().for_each(|m| *m = [f32::INFINITY; SUBWINDOWS]);
        self.sub_count = 0;
        self.sub_idx = 0;
        self.frame.iter_mut().for_each(|v| *v = 0.0);
        self.frame_raw.iter_mut().for_each(|v| *v = 0.0);
    }

    /// Minimum statistics on the current `bins`, then the median of five neighbours, times `bias`.
    fn update_floor(&mut self, bias: f32) {
        let a = self.alpha;
        for k in 0..=self.kmax {
            let p = self.bins[k].norm_sqr();
            self.ps[k] = if self.ps[k] == 0.0 { p } else { a * self.ps[k] + (1.0 - a) * p };
            self.sub_min[k] = self.sub_min[k].min(self.ps[k]);
            let m = self.mins[k].iter().fold(self.sub_min[k], |acc, &v| acc.min(v));
            self.pmin[k] = m;
        }
        self.sub_count += 1;
        if self.sub_count >= self.sub_len {
            self.sub_count = 0;
            for k in 0..=self.kmax {
                self.mins[k][self.sub_idx] = self.sub_min[k];
                self.sub_min[k] = f32::INFINITY;
            }
            self.sub_idx = (self.sub_idx + 1) % SUBWINDOWS;
        }
        for k in self.k_lo..=self.k_hi {
            let mut w = [0.0f32; 5];
            for (j, v) in w.iter_mut().enumerate() {
                *v = self.pmin[(k + j).saturating_sub(2).min(self.kmax)];
            }
            w.sort_unstable_by(|x, y| x.total_cmp(y));
            self.floor[k] = w[2] * bias;
        }
    }

    fn frame_done(&mut self) {
        for i in 0..self.n {
            self.tmp[i] = self.frame[i] * self.win[i];
        }
        self.fft.forward(&self.tmp, &mut self.bins);
        self.update_floor(self.bias);
        for k in self.k_lo..=self.k_hi {
            self.in_band += 1;
            let fl = self.floor[k];
            if self.bins[k].norm_sqr() < self.fg * fl {
                let s = (fl * 0.5).sqrt() * crate::fft::INCOHERENT_GAIN;
                self.bins[k] = C32::new(s * self.rng.normal(), s * self.rng.normal());
                self.replaced += 1;
            }
        }
        for i in 0..self.n {
            self.tmp[i] = self.frame_raw[i] * self.win[i];
        }
        self.fft.forward(&self.tmp, &mut self.bins_raw);
        for k in (0..self.k_lo).chain(self.k_hi + 1..self.bins.len()) {
            self.bins[k] = self.bins_raw[k];
        }
        self.fft.inverse(&self.bins, &mut self.tmp);
        // Hann analysis and synthesis at a quarter-window hop: the squared windows sum to 1.5
        for i in 0..self.n {
            self.ola[i] += self.tmp[i] * self.win[i] * (1.0 / 1.5);
        }
        let cap = self.outq.len();
        for i in 0..self.h {
            let w = (self.q_read + self.q_len) % cap;
            self.outq[w] = self.ola[i];
            self.q_len += 1;
        }
        self.ola.copy_within(self.h.., 0);
        let n = self.n;
        self.ola[n - self.h..].iter_mut().for_each(|v| *v = 0.0);
    }

    /// Scrub `input` into `output` (same length; may be called with any block size).
    pub fn process(&mut self, input: &[f32], output: &mut [f32]) {
        debug_assert_eq!(input.len(), output.len());
        let cap = self.outq.len();
        for (x, y) in input.iter().zip(output.iter_mut()) {
            let x = if x.is_finite() { *x } else { 0.0 };
            let v = self.stage.run(x);
            self.frame[self.n - self.h + self.fill] = v;
            self.frame_raw[self.n - self.h + self.fill] = x;
            self.fill += 1;
            if self.fill == self.h {
                self.fill = 0;
                self.frame_done();
                self.frame.copy_within(self.h.., 0);
                self.frame_raw.copy_within(self.h.., 0);
            }
            if self.q_len > 0 {
                *y = self.outq[self.q_read];
                self.q_read = (self.q_read + 1) % cap;
                self.q_len -= 1;
            } else {
                *y = 0.0;
            }
        }
    }

    /// What the scrub has done so far.
    pub fn report(&self) -> Report {
        Report {
            replaced_fraction: if self.in_band > 0 { self.replaced as f64 / self.in_band as f64 } else { 0.0 },
            ridge_fraction: 0.0,
            ridges_found: self.stage.ridges_confirmed(),
            hum_nominal_hz: self.stage.hum_nominal(),
        }
    }
}

/// Convenience for tests and the file tool's `--live`: a whole signal through the live scrub, delay removed.
pub fn scrub_live(x: &[f32], sr: f64, cfg: &Config) -> (Vec<f32>, Report) {
    let mut l = Live::new(cfg, sr);
    let lat = l.latency();
    let mut y = vec![0.0; x.len() + lat];
    let mut padded = x.to_vec();
    padded.resize(x.len() + lat, 0.0);
    for (i, o) in padded.chunks(1024).zip(y.chunks_mut(1024)) {
        l.process(i, o);
    }
    (y[lat..].to_vec(), l.report())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_is_the_reported_latency_and_highs_pass_unchanged() {
        let sr = 48000.0;
        let n = 48000 * 3;
        // a 5 kHz tone and a click well above the band
        let x: Vec<f32> = (0..n)
            .map(|i| 0.3 * (2.0 * std::f32::consts::PI * 5000.0 * i as f32 / sr as f32).sin() + if i == 70000 { 0.5 } else { 0.0 })
            .collect();
        for keep_hum in [true, false] {
            let cfg = Config { seed: Some(1), keep_hum, ..Config::default() };
            let (y, _) = scrub_live(&x, sr, &cfg);
            // the click is where the input had it once the tone is taken out
            let d: Vec<f32> = (0..n).map(|i| y[i] - 0.3 * (2.0 * std::f32::consts::PI * 5000.0 * i as f32 / sr as f32).sin()).collect();
            let peak = (60000..80000).max_by(|&a, &b| d[a].abs().total_cmp(&d[b].abs())).unwrap();
            assert!((peak as i64 - 70000).abs() <= 1, "click at {peak}: {} vs {}", d[peak], d[70000]);
            // after the first frames the output is the input (the band is empty here): error power 1e-6 against the
            // tone's 0.045, under -46 dB
            let err: f32 = (24000..n - 2000).map(|i| (y[i] - x[i]).powi(2)).sum::<f32>() / (n - 26000) as f32;
            assert!(err < 1e-6, "{err}");
        }
    }
}
