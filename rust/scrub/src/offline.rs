//! The whole-file scrub, with lookahead: a port of flyover-scrub's `scrub()` (MIT, lizTheDeveloper; see NOTICE).
//!
//! For every STFT bin in the protected band:
//!
//! | bin | treatment |
//! | --- | --- |
//! | background (under `foreground_db` above the local floor) | re-synthesised: fresh random-phase noise at the local mean power |
//! | part of a long, slowly gliding narrowband ridge | replaced by noise at the floor's level (removed) |
//! | other foreground (speech, music, transients) | untouched |
//!
//! Why not a filter: the attack is a matched filter that adds up energy along a long, precisely predicted curve, so it
//! recovers lines far below the noise and lines that were only made quieter. The bins have to carry no information about
//! the curve.
//!
//! Differences from the reference, all deliberate:
//! - Streaming in blocks of a minute with ten seconds of context on each side, so an hour of audio needs megabytes, not
//!   gigabytes. The reference's whole-file level corrections (one number per frequency) are per block here.
//! - Window lengths are powers of two (0.17-0.34 s instead of exactly 0.25 s), for our own FFT.
//! - Only the in-band bins are kept: the output is the input plus the inverse STFT of the change, so everything above the
//!   band is the input sample for sample.
//! - Mains hum is also removed by tracking notches before the STFT (`stage`), so ENF is gone even where speech keeps a bin.

use std::collections::VecDeque;

use crate::complex::C32;
use crate::config::{Config, Report};
use crate::fft::{floor_pow2, hann, RealFft};
use crate::nd::{self, Shape};
use crate::rng::Rng;
use crate::stage::TimeStage;

const LN2: f32 = std::f32::consts::LN_2;

pub struct Offline {
    cfg: Config,
    nw: usize,
    hop: usize,
    fft: RealFft,
    win: Vec<f32>,
    stage: Option<TimeStage>,
    kb0: usize,
    nb: usize,
    /// in-band bins, relative to kb0
    b_lo: usize,
    b_hi: usize,
    df: f32,
    dt: f32,
    nf: usize,
    nt: usize,
    min_frames: usize,
    max_bins: usize,
    pad: usize,
    /// the input as it came (the output is this plus `corr`)
    x: Vec<f32>,
    /// the input after the hum notches (what the STFT analyses); empty when hum is kept
    xh: Vec<f32>,
    corr: Vec<f32>,
    x_base: usize,
    frames: VecDeque<Vec<C32>>,
    f_base: usize,
    next_frame: usize,
    done_upto: usize,
    total_in: usize,
    finished: bool,
    block: usize,
    ctx: usize,
    rng: Rng,
    frame_buf: Vec<f32>,
    spec: Vec<C32>,
    inband_total: u64,
    replaced: u64,
    ridge_bins: u64,
    ridges_found: usize,
}

impl Offline {
    pub fn new(cfg: &Config, sr: f64) -> Offline {
        // the largest power of two not longer than the window (0.17 s at 48 kHz): shorter windows follow a voice better
        let nw = floor_pow2(cfg.window_s as f64 * sr).max(16);
        let hop = nw / 4;
        let df = (sr / nw as f64) as f32;
        let dt = (hop as f64 / sr) as f32;
        let nf = (((cfg.floor_freq_hz / df).round() as usize) | 1).max(3);
        let nt = (((cfg.floor_time_s / dt).round() as usize) | 1).max(1);
        let k_lo = (cfg.band.0 / df).ceil().max(0.0) as usize;
        let k_hi = ((cfg.band.1 / df).floor() as usize).min(nw / 2);
        let margin = nf;
        let kb0 = k_lo.saturating_sub(margin);
        let kb1 = (k_hi + margin).min(nw / 2);
        let mut rng = Rng::new(cfg.seed);
        let stage = (!cfg.keep_hum).then(|| TimeStage::new(cfg, sr, false, Rng::seeded(rng.next_u64())));
        Offline {
            cfg: cfg.clone(),
            nw,
            hop,
            fft: RealFft::new(nw),
            win: hann(nw),
            stage,
            kb0,
            nb: kb1 - kb0 + 1,
            b_lo: k_lo - kb0,
            b_hi: k_hi - kb0,
            df,
            dt,
            nf,
            nt,
            min_frames: (cfg.ridge_min_s / dt).ceil() as usize,
            max_bins: ((cfg.ridge_max_slope_hz_s * dt / df).ceil() as usize).max(1),
            pad: ((cfg.ridge_pad_hz / df).round() as usize).max(1),
            x: Vec::new(),
            xh: Vec::new(),
            corr: Vec::new(),
            x_base: 0,
            frames: VecDeque::new(),
            f_base: 0,
            next_frame: 0,
            done_upto: 0,
            total_in: 0,
            finished: false,
            block: (60.0 / dt).ceil() as usize,
            ctx: (10.0 / dt).ceil() as usize,
            rng,
            frame_buf: vec![0.0; nw],
            spec: vec![C32::ZERO; nw / 2 + 1],
            inband_total: 0,
            replaced: 0,
            ridge_bins: 0,
            ridges_found: 0,
        }
    }

    fn frame_start(&self, j: usize) -> isize {
        (j * self.hop) as isize - (self.nw - self.hop) as isize
    }

    /// Frames that cover any input sample: j with start < total_in.
    fn frames_total(&self) -> usize {
        (self.total_in + self.nw - self.hop).div_ceil(self.hop)
    }

    /// Frame `j`'s in-band bins: of the notched input first, then of the raw input (the notches' phase reaches above the
    /// band a little, so the output is built on the raw input and only the band takes the notched version).
    fn compute_frame(&mut self, j: usize) {
        let s = self.frame_start(j);
        let mut bins = Vec::with_capacity(2 * self.nb);
        let sources: &[bool] = if self.stage.is_some() { &[true, false] } else { &[false] };
        for &notched in sources {
            let src = if notched { &self.xh } else { &self.x };
            for i in 0..self.nw {
                let t = s + i as isize;
                let v = if t < 0 || t as usize >= self.total_in { 0.0 } else { src[t as usize - self.x_base] };
                self.frame_buf[i] = v * self.win[i];
            }
            self.fft.forward(&self.frame_buf, &mut self.spec);
            bins.extend_from_slice(&self.spec[self.kb0..self.kb0 + self.nb]);
        }
        self.frames.push_back(bins);
    }

    /// Feed input samples.
    pub fn push(&mut self, input: &[f32]) {
        for &v in input {
            let v = if v.is_finite() { v } else { 0.0 };
            if let Some(st) = self.stage.as_mut() {
                self.xh.push(st.run(v));
            }
            self.x.push(v);
            self.corr.push(0.0);
        }
        self.total_in += input.len();
        while self.next_frame * self.hop + self.hop <= self.total_in {
            self.compute_frame(self.next_frame);
            self.next_frame += 1;
        }
        while self.next_frame >= self.done_upto + self.block + self.ctx {
            let c0 = self.done_upto;
            self.process(c0, c0 + self.block, c0 + self.block + self.ctx);
        }
    }

    /// No more input: process what is left.
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let total = self.frames_total();
        while self.next_frame < total {
            self.compute_frame(self.next_frame);
            self.next_frame += 1;
        }
        while self.done_upto < total {
            let c0 = self.done_upto;
            let c1 = (c0 + self.block).min(total);
            self.process(c0, c1, (c1 + self.ctx).min(total));
        }
    }

    /// Append the scrubbed samples that are final to `out`.
    pub fn pull(&mut self, out: &mut Vec<f32>) {
        let fin =
            if self.finished { self.total_in } else { ((self.done_upto * self.hop + self.hop).saturating_sub(self.nw)).min(self.total_in) };
        if fin <= self.x_base {
            return;
        }
        let m = fin - self.x_base;
        out.extend(self.x[..m].iter().zip(&self.corr[..m]).map(|(a, b)| a + b));
        self.x.drain(..m);
        if !self.xh.is_empty() {
            self.xh.drain(..m);
        }
        self.corr.drain(..m);
        self.x_base = fin;
    }

    /// One block: frames [c0, c1) are scrubbed, using frames [c0 - ctx, w1) for context.
    fn process(&mut self, c0: usize, c1: usize, w1: usize) {
        let w0 = c0.saturating_sub(self.ctx).max(self.f_base);
        let s = Shape { nt: w1 - w0, nb: self.nb };
        let cfg = &self.cfg;
        let nb = self.nb;
        let n = s.nt * nb;
        let z = |t: usize, k: usize| self.frames[t + w0 - self.f_base][k];
        let raw_off = if self.stage.is_some() { nb } else { 0 };
        let z_raw = |t: usize, k: usize| self.frames[t + w0 - self.f_base][raw_off + k];

        let mut mag = vec![0.0f32; n];
        let mut logm = vec![0.0f32; n];
        for t in 0..s.nt {
            for k in 0..nb {
                let m = z(t, k).abs();
                mag[t * nb + k] = m;
                logm[t * nb + k] = (m + 1e-12).ln();
            }
        }
        let mut med = vec![0.0f32; n];
        nd::median_freq(&logm, s, self.nf, &mut med);
        let mut fl = vec![0.0f32; n];
        nd::uniform_time(&med, s, self.nt, &mut fl);
        let floor: Vec<f32> = fl.iter().map(|v| v.exp()).collect();
        let inband = |k: usize| k >= self.b_lo && k <= self.b_hi;
        let mut ratio = vec![-99.0f32; n];
        for i in 0..n {
            if inband(i % nb) {
                ratio[i] = 20.0 * ((mag[i] + 1e-12) / (floor[i] + 1e-12)).log10();
            }
        }

        // ridges: peaks across frequency, one-frame gaps bridged, joined within the glide an aircraft can make
        let mut peak = vec![false; n];
        for t in 0..s.nt {
            for k in 0..nb {
                let r = ratio[t * nb + k];
                let l = ratio[t * nb + k.saturating_sub(1)];
                let h = ratio[t * nb + (k + 1).min(nb - 1)];
                peak[t * nb + k] = r > cfg.ridge_db && r >= l && r >= h;
            }
        }
        let closed = nd::close_time(&peak, s, 3);
        let bridged: Vec<bool> = peak.iter().zip(&closed).map(|(a, b)| *a || *b).collect();
        let (lab, boxes) = nd::label(&bridged, s, self.max_bins, 1);
        let mut keep = vec![false; boxes.len() + 1];
        for (i, b) in boxes.iter().enumerate() {
            let t_ext = b.t1 - b.t0 + 1;
            let f_ext = b.k1 - b.k0 + 1;
            if t_ext < self.min_frames {
                continue;
            }
            if f_ext as f32 * self.df > cfg.ridge_max_slope_hz_s * t_ext as f32 * self.dt + 6.0 * self.df {
                continue;
            }
            if cfg.keep_hum && f_ext as f32 * self.df <= cfg.stationary_max_drift_hz + 2.0 * self.df {
                continue;
            }
            keep[i + 1] = true;
            let t0 = w0 + b.t0;
            if t0 >= c0 && t0 < c1 {
                self.ridges_found += 1;
            }
        }
        let ridge_px: Vec<bool> = lab.iter().map(|&l| keep[l as usize]).collect();
        let ridge = nd::dilate(&ridge_px, s, self.pad, 1);

        let mut replace = vec![false; n];
        let mut bgm = vec![false; n];
        for i in 0..n {
            let ib = inband(i % nb);
            let bg = ratio[i] < cfg.foreground_db;
            replace[i] = ib && (bg || ridge[i]);
            bgm[i] = ib && bg && !ridge[i];
        }

        // noise for the core frames only
        let (r0, r1) = (c0 - w0, c1 - w0);
        let mut noise = vec![C32::ZERO; (r1 - r0) * nb];
        for t in r0..r1 {
            for k in self.b_lo..=self.b_hi {
                let i = t * nb + k;
                if !replace[i] {
                    continue;
                }
                // the mean power of noise whose median magnitude is the floor; the reference uses the local mean power of
                // the background bins instead, which next to speech takes in the voice's quieter parts and spreads them
                // into the pauses as louder room tone (measured: +6 dB between words)
                let sigma = floor[i] / LN2.sqrt();
                let s2 = sigma * std::f32::consts::FRAC_1_SQRT_2;
                noise[(t - r0) * nb + k] = C32::new(s2 * self.rng.normal(), s2 * self.rng.normal());
            }
        }
        // level corrections from the block's totals (one number per frequency, smoothed across frequency): the quiet
        // background (under 6 dB above the floor) keeps its level, without bringing back any time-varying structure
        // (within +-3 dB); and replaced bins never total more power than the bins they replace
        let mut p_in = vec![0.0f64; nb];
        let mut p_out = vec![0.0f64; nb];
        let mut p_orig = vec![0.0f64; nb];
        for t in r0..r1 {
            for k in 0..nb {
                let i = t * nb + k;
                let nz = noise[(t - r0) * nb + k].norm_sqr() as f64;
                let m2 = (mag[i] * mag[i]) as f64;
                if bgm[i] && ratio[i] < 6.0 {
                    p_in[k] += m2;
                    p_out[k] += nz;
                }
                if replace[i] {
                    p_orig[k] += m2;
                }
            }
        }
        let si = nd::uniform_1d(&p_in, self.nf);
        let so = nd::uniform_1d(&p_out, self.nf);
        let gain: Vec<f32> = si
            .iter()
            .zip(&so)
            // bins under 6 dB are the lower 81.5 % of noise power (exponential, cut at 4 ln 2 times its median-based mean)
            .map(|(a, b)| if *b > 1e-20 { (a.max(0.0) / (0.815 * b)).sqrt().clamp(0.708, 1.413) as f32 } else { 1.0 })
            .collect();
        let mut p_new = vec![0.0f64; nb];
        for t in r0..r1 {
            for k in 0..nb {
                let i = t * nb + k;
                let v = &mut noise[(t - r0) * nb + k];
                if bgm[i] {
                    *v = v.scale(gain[k]);
                }
                if replace[i] {
                    p_new[k] += v.norm_sqr() as f64;
                }
            }
        }
        let cap: Vec<f32> = p_orig.iter().zip(&p_new).map(|(o, nw)| (o / nw.max(1e-30)).sqrt().min(1.0) as f32).collect();

        // the change, back to time and added to the input
        let mut full = vec![C32::ZERO; self.nw / 2 + 1];
        let mut back = vec![0.0f32; self.nw];
        for t in r0..r1 {
            full.iter_mut().for_each(|v| *v = C32::ZERO);
            let mut any = raw_off > 0;
            for k in self.b_lo..=self.b_hi {
                let i = t * nb + k;
                self.inband_total += 1;
                let new = if replace[i] {
                    self.replaced += 1;
                    if ridge[i] {
                        self.ridge_bins += 1;
                    }
                    any = true;
                    noise[(t - r0) * nb + k].scale(cap[k] * crate::fft::INCOHERENT_GAIN)
                } else {
                    z(t, k)
                };
                full[self.kb0 + k] = new - z_raw(t, k);
            }
            if !any {
                continue;
            }
            self.fft.inverse(&full, &mut back);
            let start = self.frame_start(w0 + t);
            for (i, b) in back.iter().enumerate() {
                let pos = start + i as isize;
                if pos < self.x_base as isize || pos as usize >= self.total_in {
                    continue;
                }
                self.corr[pos as usize - self.x_base] += b * self.win[i] * (1.0 / 1.5);
            }
        }
        self.done_upto = c1;
        let keep_from = self.done_upto.saturating_sub(self.ctx);
        while self.f_base < keep_from {
            self.frames.pop_front();
            self.f_base += 1;
        }
    }

    pub fn report(&self) -> Report {
        let tot = self.inband_total.max(1) as f64;
        Report {
            replaced_fraction: self.replaced as f64 / tot,
            ridge_fraction: self.ridge_bins as f64 / tot,
            ridges_found: self.ridges_found,
            hum_nominal_hz: self.stage.as_ref().map_or(0, |s| s.hum_nominal()),
        }
    }
}

/// A whole signal through the whole-file scrub.
pub fn scrub(x: &[f32], sr: f64, cfg: &Config) -> (Vec<f32>, Report) {
    let mut o = Offline::new(cfg, sr);
    let mut y = Vec::with_capacity(x.len());
    for c in x.chunks(1 << 16) {
        o.push(c);
        o.pull(&mut y);
    }
    o.finish();
    o.pull(&mut y);
    (y, o.report())
}
