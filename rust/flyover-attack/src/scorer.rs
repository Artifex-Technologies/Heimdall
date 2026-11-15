//! The brightness scorer (port of flyover-scrub's attack.py, MIT): for each candidate place, model the exact Doppler curve
//! the track would produce there and add up the whitened spectrogram's energy under it, over a few harmonics, sweeping
//! the unknown source pitch and a small clock offset. The place whose curve covers the observed line best wins.

use heimdall_scrub::complex::C32;
use heimdall_scrub::fft::{hann, nearest_pow2, RealFft};

use crate::physics::{Heard, Track};

/// A whitened log-power spectrogram, frequency-major: `s[k * nt + t]`.
#[derive(Clone)]
pub struct Spectrogram {
    pub s: Vec<f32>,
    pub nf: usize,
    pub nt: usize,
    pub df: f64,
    /// seconds from the start of the audio, frame centres
    pub times: Vec<f64>,
}

impl Spectrogram {
    /// The same spectrogram played backwards: aircraft lines rise instead of fall, so a modelled flyover can only match
    /// it by chance. It keeps every other statistic of the recording, which makes it the fair null.
    pub fn reversed(&self) -> Spectrogram {
        let mut s = self.s.clone();
        for k in 0..self.nf {
            s[k * self.nt..(k + 1) * self.nt].reverse();
        }
        Spectrogram { s, ..self.clone() }
    }
}

fn median(v: &mut [f32]) -> f32 {
    let n = v.len();
    v.sort_unstable_by(|a, b| a.total_cmp(b));
    if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    }
}

/// Long-window spectrogram, whitened per frequency (each bin divided by its median over time, then the local median over
/// nine bins of frequency taken out), so faint lines nobody can hear stand out. Equivalent to "boosting" after a high-pass.
pub fn whitened_spectrogram(audio: &[f32], sr: f64, window_s: f64, hop_s: f64, fmax: f64) -> Spectrogram {
    let n = nearest_pow2(window_s * sr);
    let hop = ((hop_s * sr).round() as usize).max(1);
    let df = sr / n as f64;
    let nf = ((fmax / df).floor() as usize + 1).min(n / 2 + 1);
    let nt = if audio.len() >= n { (audio.len() - n) / hop + 1 } else { 0 };
    let mut fft = RealFft::new(n);
    let w = hann(n);
    let mut buf = vec![0.0f32; n];
    let mut bins = vec![C32::ZERO; n / 2 + 1];
    let mut p = vec![0.0f32; nf * nt];
    for t in 0..nt {
        for i in 0..n {
            buf[i] = audio[t * hop + i] * w[i];
        }
        fft.forward(&buf, &mut bins);
        for k in 0..nf {
            p[k * nt + t] = bins[k].norm_sqr() + 1e-20;
        }
    }
    let mut l = vec![0.0f32; nf * nt];
    let mut row = vec![0.0f32; nt];
    for k in 0..nf {
        row.copy_from_slice(&p[k * nt..(k + 1) * nt]);
        let m = if nt > 0 { median(&mut row) } else { 1.0 };
        for t in 0..nt {
            l[k * nt + t] = (p[k * nt + t] / m).ln();
        }
    }
    let mut s = vec![0.0f32; nf * nt];
    let mut win = [0.0f32; 9];
    for t in 0..nt {
        for k in 0..nf {
            for (j, v) in win.iter_mut().enumerate() {
                let kk = (k + j).saturating_sub(4).min(nf - 1);
                *v = l[kk * nt + t];
            }
            let m = median(&mut win);
            s[k * nt + t] = (l[k * nt + t] - m).clamp(-3.0, 8.0);
        }
    }
    let times = (0..nt).map(|t| (t * hop) as f64 / sr + n as f64 / 2.0 / sr).collect();
    Spectrogram { s, nf, nt, df, times }
}

/// What the scorer explores at each place.
#[derive(Clone, Debug)]
pub struct Sweep {
    /// range of the source's fundamental, Hz
    pub f0_range: (f64, f64),
    pub f0_step: f64,
    /// clock errors tried, seconds (the recording's start on the flight data's clock may be off)
    pub offsets: Vec<f64>,
    pub n_harmonics: usize,
}

impl Default for Sweep {
    fn default() -> Sweep {
        Sweep { f0_range: (40.0, 400.0), f0_step: 0.25, offsets: (0..=32).map(|i| -4.0 + 0.25 * i as f64).collect(), n_harmonics: 3 }
    }
}

/// Scores for a set of candidate places (local metres).
#[derive(Clone, Debug)]
pub struct Scored {
    pub candidates: Vec<[f64; 3]>,
    pub scores: Vec<f64>,
    pub best_f0: Vec<f64>,
    pub best_offset: Vec<f64>,
}

impl Scored {
    /// Candidate indices, best first.
    pub fn ranked(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.scores.len()).collect();
        o.sort_by(|&a, &b| self.scores[b].total_cmp(&self.scores[a]));
        o
    }

    fn extend(&mut self, o: Scored) {
        self.candidates.extend(o.candidates);
        self.scores.extend(o.scores);
        self.best_f0.extend(o.best_f0);
        self.best_offset.extend(o.best_offset);
    }
}

/// Score every candidate. `audio_t0` is the recording's start on the tracks' clock; with several tracks the clock offset
/// is shared between them (locked), which is what makes two flights so constraining.
pub fn score_candidates(spec: &Spectrogram, tracks: &[Track], audio_t0: f64, candidates: &[[f64; 3]], sweep: &Sweep) -> Scored {
    let nf0 = ((sweep.f0_range.1 - sweep.f0_range.0) / sweep.f0_step + 1e-9).floor() as usize + 1;
    let f0s: Vec<f64> = (0..nf0).map(|i| sweep.f0_range.0 + i as f64 * sweep.f0_step).collect();
    let no = sweep.offsets.len();
    let nt = spec.nt;
    let mut out = Scored {
        candidates: candidates.to_vec(),
        scores: vec![f64::NEG_INFINITY; candidates.len()],
        best_f0: vec![0.0; candidates.len()],
        best_offset: vec![0.0; candidates.len()],
    };
    let mut total = vec![0.0f64; no * nf0];
    let mut g = vec![0.0f64; nt];
    let mut w = vec![0.0f64; nt];
    for (ci, obs) in candidates.iter().enumerate() {
        total.iter_mut().for_each(|v| *v = 0.0);
        for trk in tracks {
            let heard = Heard::new(trk, *obs);
            for (oi, off) in sweep.offsets.iter().enumerate() {
                let mut wsum = 0.0;
                for t in 0..nt {
                    match heard.at(audio_t0 + off + spec.times[t]) {
                        Some((gg, r, _)) if r < 12000.0 => {
                            g[t] = gg;
                            w[t] = 1.0 / r.max(300.0);
                            wsum += w[t];
                        }
                        _ => {
                            g[t] = 0.0;
                            w[t] = 0.0;
                        }
                    }
                }
                if wsum <= 0.0 {
                    continue;
                }
                let norm = 1.0 / (wsum + 1e-12) / sweep.n_harmonics as f64;
                for (fi, f0) in f0s.iter().enumerate() {
                    let mut acc = 0.0f64;
                    for t in 0..nt {
                        if w[t] == 0.0 {
                            continue;
                        }
                        let mut v = 0.0f64;
                        for k in 1..=sweep.n_harmonics {
                            let fb = f0 * k as f64 * g[t] / spec.df;
                            if fb < (spec.nf - 1) as f64 {
                                let b = fb.round().max(0.0) as usize;
                                v += spec.s[b * nt + t] as f64;
                            }
                        }
                        acc += v * w[t];
                    }
                    total[oi * nf0 + fi] += acc * norm;
                }
            }
        }
        let (j, best) = total.iter().enumerate().fold((0, f64::NEG_INFINITY), |a, (i, &v)| if v > a.1 { (i, v) } else { a });
        out.scores[ci] = best;
        out.best_offset[ci] = sweep.offsets[j / nf0];
        out.best_f0[ci] = f0s[j % nf0];
    }
    out
}

/// A square grid of points (local metres) around `center`, `half_width` each way, every `step`.
pub fn grid(center: (f64, f64), half_width: f64, step: f64, z: f64) -> Vec<[f64; 3]> {
    let n = (2.0 * half_width / step + 1e-9).floor() as usize + 1;
    let mut v = Vec::with_capacity(n * n);
    for iy in 0..n {
        for ix in 0..n {
            v.push([center.0 - half_width + ix as f64 * step, center.1 - half_width + iy as f64 * step, z]);
        }
    }
    v
}

/// The search box: a coarse grid, then a fine grid around the best coarse cells.
#[derive(Clone, Debug)]
pub struct Box2 {
    pub center: (f64, f64),
    pub half_width: f64,
    pub coarse: f64,
    pub fine: f64,
    pub refine_top: usize,
}

impl Default for Box2 {
    fn default() -> Box2 {
        Box2 { center: (0.0, 0.0), half_width: 5000.0, coarse: 250.0, fine: 50.0, refine_top: 12 }
    }
}

/// Coarse grid, then refinement around the best coarse cells (as in the video).
pub fn locate(spec: &Spectrogram, tracks: &[Track], audio_t0: f64, area: &Box2, sweep: &Sweep) -> Scored {
    let c = grid(area.center, area.half_width, area.coarse, 0.0);
    let mut res = score_candidates(spec, tracks, audio_t0, &c, sweep);
    let mut fine: Vec<[f64; 3]> = Vec::new();
    for &i in res.ranked().iter().take(area.refine_top) {
        for p in grid((c[i][0], c[i][1]), area.coarse, area.fine, 0.0) {
            let q = [(p[0] * 10.0).round() / 10.0, (p[1] * 10.0).round() / 10.0, 0.0];
            if !fine.iter().any(|f| f[0] == q[0] && f[1] == q[1]) {
                fine.push(q);
            }
        }
    }
    let res2 = score_candidates(spec, tracks, audio_t0, &fine, sweep);
    res.extend(res2);
    res
}

/// "Signal times chance": how far the best place stands above the same search on the time-reversed spectrogram,
/// (best - median of null) / (max of null - median of null). About 0.5 with no aircraft, 1-2 after scrubbing, 20-35 for an
/// inaudible synthetic flyover (the reference's calibration); 4 or more reads as a real line. NaN without a usable null.
pub fn strength_vs_chance(found: &Scored, null: &Scored) -> f64 {
    let mut n: Vec<f64> = null.scores.iter().copied().filter(|v| v.is_finite()).collect();
    if n.len() < 50 {
        return f64::NAN;
    }
    n.sort_by(|a, b| a.total_cmp(b));
    let med = n[n.len() / 2];
    let spread = n[n.len() - 1] - med;
    let top = found.scores.iter().copied().filter(|v| v.is_finite()).fold(f64::NEG_INFINITY, f64::max);
    if spread > 1e-6 {
        (top - med) / spread
    } else {
        f64::NAN
    }
}
