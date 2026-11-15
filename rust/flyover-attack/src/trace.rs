//! Trace and fit (port of flyover-scrub's trace.py, MIT), the stronger attack on real recordings: follow the visible line
//! frame by frame, then for each candidate place solve the source pitch in closed form (log f_obs = log f0 + log g) and
//! score the RMS residual in cents. `reversal_ratio` is its chance check: a real flyover only falls in pitch, so its
//! reversal fits badly; a steady hum or a random wander fits both ways about equally.

use crate::physics::{Heard, Track};
use crate::scorer::{grid, Box2, Scored, Spectrogram};

const CENTS_PER_LOG: f64 = 1200.0 / std::f64::consts::LN_2;

/// A followed line: frame times (s from the audio start) and frequencies (Hz).
#[derive(Clone, Debug, Default)]
pub struct Ridge {
    pub t: Vec<f64>,
    pub f: Vec<f64>,
}

impl Ridge {
    pub fn len(&self) -> usize {
        self.t.len()
    }

    pub fn is_empty(&self) -> bool {
        self.t.is_empty()
    }

    /// The same frames with the frequencies backwards (rising instead of falling).
    pub fn reversed(&self) -> Ridge {
        let mut f = self.f.clone();
        f.reverse();
        Ridge { t: self.t.clone(), f }
    }
}

/// Follow one line from its strongest point inside `f_range` (Hz) and `t_range` (s), allowing `follow_hz` of movement a
/// frame, and keep the frames where it is strong (`min_strength` whitened log units) and continuous.
pub fn trace_ridge(spec: &Spectrogram, f_range: (f64, f64), t_range: Option<(f64, f64)>, follow_hz: f64, min_strength: f32) -> Ridge {
    let ks: Vec<usize> = (0..spec.nf).filter(|&k| (k as f64 * spec.df) >= f_range.0 && (k as f64 * spec.df) <= f_range.1).collect();
    let ts: Vec<usize> = (0..spec.nt).filter(|&t| t_range.is_none_or(|(a, b)| spec.times[t] >= a && spec.times[t] <= b)).collect();
    if ks.len() < 3 || ts.is_empty() {
        return Ridge::default();
    }
    let s = |k: usize, t: usize| spec.s[ks[k] * spec.nt + ts[t]];
    let nk = ks.len();
    let w = ((follow_hz / spec.df).round() as usize).max(1);
    let (mut j0, mut k0, mut best) = (0, 0, f32::NEG_INFINITY);
    for t in 0..ts.len() {
        for k in 0..nk {
            if s(k, t) > best {
                (best, j0, k0) = (s(k, t), t, k);
            }
        }
    }
    let mut kk = vec![0usize; ts.len()];
    kk[j0] = k0;
    let follow = |range: &mut dyn Iterator<Item = usize>, kk: &mut Vec<usize>| {
        let mut prev = k0;
        for j in range {
            let (lo, hi) = (prev.saturating_sub(w), (prev + w + 1).min(nk));
            let k = (lo..hi).max_by(|&a, &b| s(a, j).total_cmp(&s(b, j))).unwrap();
            kk[j] = k;
            prev = k;
        }
    };
    follow(&mut (j0 + 1..ts.len()), &mut kk);
    follow(&mut (0..j0).rev(), &mut kk);
    let fr: Vec<f64> = (0..ts.len())
        .map(|j| {
            let k = kk[j].clamp(1, nk - 2);
            let (y0, y1, y2) = (s(k - 1, j) as f64, s(k, j) as f64, s(k + 1, j) as f64);
            let den = y0 - 2.0 * y1 + y2;
            let d = if den.abs() > 1e-9 { 0.5 * (y0 - y2) / den } else { 0.0 };
            ks[k] as f64 * spec.df + d.clamp(-0.5, 0.5) * spec.df
        })
        .collect();
    let mut out = Ridge::default();
    for j in 0..ts.len() {
        let lo = j.saturating_sub(4);
        let hi = (j + 5).min(ts.len());
        let mut win: Vec<f64> = fr[lo..hi].to_vec();
        win.sort_by(|a, b| a.total_cmp(b));
        let smooth = win[win.len() / 2];
        if s(kk[j], j) > min_strength && (fr[j] - smooth).abs() < 1.5 {
            out.t.push(spec.times[ts[j]]);
            out.f.push(fr[j]);
        }
    }
    out
}

/// RMS residual in cents, best source pitch and best clock offset, for each candidate.
pub fn fit_candidates(ridge: &Ridge, track: &Track, audio_t0: f64, candidates: &[[f64; 3]], offsets: &[f64]) -> Scored {
    let n = ridge.len();
    let lf: Vec<f64> = ridge.f.iter().map(|f| f.ln()).collect();
    let mut out = Scored {
        candidates: candidates.to_vec(),
        scores: vec![f64::NEG_INFINITY; candidates.len()],
        best_f0: vec![0.0; candidates.len()],
        best_offset: vec![0.0; candidates.len()],
    };
    for (ci, c) in candidates.iter().enumerate() {
        let heard = Heard::new(track, *c);
        let mut best = (f64::INFINITY, 0.0, 0.0);
        for &off in offsets {
            let lg: Vec<Option<f64>> =
                ridge.t.iter().map(|t| heard.at(audio_t0 + off + t).and_then(|(g, _, _)| (g > 0.0).then(|| g.ln()))).collect();
            let ok = lg.iter().filter(|v| v.is_some()).count();
            if (ok as f64) <= 0.8 * n as f64 {
                continue;
            }
            let lf0 = lg.iter().zip(&lf).filter_map(|(g, f)| g.map(|g| f - g)).sum::<f64>() / ok as f64;
            let rms = (lg.iter().zip(&lf).filter_map(|(g, f)| g.map(|g| (f - g - lf0).powi(2))).sum::<f64>() / ok as f64).sqrt();
            if rms < best.0 {
                best = (rms, lf0.exp(), off);
            }
        }
        if best.0.is_finite() {
            // higher is better everywhere: scores are negative cents
            out.scores[ci] = -best.0 * CENTS_PER_LOG;
            out.best_f0[ci] = best.1;
            out.best_offset[ci] = best.2;
        }
    }
    out
}

/// Coarse grid then refinement, by fit.
pub fn locate_trace(ridge: &Ridge, track: &Track, audio_t0: f64, area: &Box2, offsets: &[f64]) -> Scored {
    let c = grid(area.center, area.half_width, area.coarse, 0.0);
    let mut res = fit_candidates(ridge, track, audio_t0, &c, offsets);
    let mut fine: Vec<[f64; 3]> = Vec::new();
    if res.scores.iter().any(|s| s.is_finite()) {
        for &i in res.ranked().iter().take(area.refine_top) {
            for p in grid((c[i][0], c[i][1]), area.coarse, area.fine, 0.0) {
                let q = [(p[0] * 10.0).round() / 10.0, (p[1] * 10.0).round() / 10.0, 0.0];
                if !fine.iter().any(|f| f[0] == q[0] && f[1] == q[1]) {
                    fine.push(q);
                }
            }
        }
    }
    let r2 = fit_candidates(ridge, track, audio_t0, &fine, offsets);
    res.candidates.extend(r2.candidates);
    res.scores.extend(r2.scores);
    res.best_f0.extend(r2.best_f0);
    res.best_offset.extend(r2.best_offset);
    res
}

/// Best reversed-ridge fit over best forward fit, on the forward search's top candidates plus a spread of the rest.
/// About 1 is chance; a real flyover gives several times more (3 is the reference's line).
pub fn reversal_ratio(ridge: &Ridge, track: &Track, audio_t0: f64, result: &Scored, offsets: &[f64]) -> f64 {
    let fwd = -result.scores.iter().copied().filter(|s| s.is_finite()).fold(f64::NEG_INFINITY, f64::max);
    if !fwd.is_finite() {
        return f64::NAN;
    }
    let ranked = result.ranked();
    let mut cand: Vec<[f64; 3]> = ranked.iter().take(200).map(|&i| result.candidates[i]).collect();
    let rest: Vec<[f64; 3]> = result.candidates.iter().zip(&result.scores).filter(|(_, s)| s.is_finite()).map(|(c, _)| *c).collect();
    let m = rest.len().min(400);
    for i in 0..m {
        cand.push(rest[i * (rest.len() - 1) / (m - 1).max(1)]);
    }
    let rev = fit_candidates(&ridge.reversed(), track, audio_t0, &cand, offsets);
    let best_rev = -rev.scores.iter().copied().filter(|s| s.is_finite()).fold(f64::NEG_INFINITY, f64::max);
    best_rev / fwd.max(1e-6)
}
