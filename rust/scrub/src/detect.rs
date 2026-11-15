//! Reporting detectors (ports of flyover-scrub's `detect_enf` and `detect_ridges`): what `heimdall-scrub --check` prints,
//! and what the tests use to show the scrub removed the hum. A detector finding nothing is not proof of absence: a matched
//! filter can still recover lines under the floor, so scrub anyway when the place matters.

use crate::complex::C32;
use crate::config::Config;
use crate::fft::{hann, nearest_pow2, RealFft};
use crate::filters::Decimator;
use crate::nd::{self, Shape};

/// `x` decimated to about 8 kHz; returns the samples and their rate.
pub fn to_8k(x: &[f32], sr: f64) -> (Vec<f32>, f64) {
    let factor = (sr / 8000.0).round().max(1.0) as usize;
    let mut d = Decimator::new(factor);
    (x.iter().filter_map(|&v| d.push(v)).collect(), sr / factor as f64)
}

/// A power or magnitude spectrogram: `s[t * nk + k]`, frequencies `k * df`, frames every `dt` seconds.
pub struct Spec {
    pub s: Vec<f32>,
    pub nt: usize,
    pub nk: usize,
    pub df: f64,
    pub dt: f64,
}

/// |STFT| (Hann, `n` points, hop `hop`, no padding at the ends), keeping bins below `fmax`.
pub fn stft_mag(x: &[f32], sr: f64, n: usize, hop: usize, fmax: f64) -> Spec {
    let df = sr / n as f64;
    let nk = ((fmax / df).floor() as usize + 1).min(n / 2 + 1);
    let mut fft = RealFft::new(n);
    let w = hann(n);
    let mut buf = vec![0.0f32; n];
    let mut bins = vec![C32::ZERO; n / 2 + 1];
    let nt = if x.len() >= n { (x.len() - n) / hop + 1 } else { 0 };
    let mut s = vec![0.0f32; nt * nk];
    for t in 0..nt {
        for i in 0..n {
            buf[i] = x[t * hop + i] * w[i];
        }
        fft.forward(&buf, &mut bins);
        for k in 0..nk {
            s[t * nk + k] = bins[k].abs();
        }
    }
    Spec { s, nt, nk, df, dt: hop as f64 / sr }
}

/// Mains hum carrying the grid frequency (ENF).
#[derive(Clone, Debug, Default)]
pub struct Enf {
    pub present: bool,
    pub nominal_hz: u32,
    /// harmonics that stand out, with their height above the neighbouring bins (dB)
    pub lines: Vec<(u32, f64)>,
    /// the median implied grid frequency
    pub grid_hz: f64,
    /// its standard deviation over the clip
    pub wander_hz: f64,
}

impl Enf {
    pub fn describe(&self) -> String {
        if !self.present {
            return "no grid hum (ENF) detected".into();
        }
        let lines: Vec<String> = self.lines.iter().map(|(h, db)| format!("{h} Hz +{db:.0} dB")).collect();
        format!(
            "grid hum (ENF) present: {} Hz grid at {:.3} Hz (wander {:.3} Hz) from {}. It can date the recording and tells \
             which power grid it was made on.",
            self.nominal_hz,
            self.grid_hz,
            self.wander_hz,
            lines.join(", ")
        )
    }
}

fn median(v: &mut [f64]) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_unstable_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    }
}

/// Looks for ENF in mono audio (about 30 s or more needed): at least two harmonics of 50 or 60 Hz stand 8 dB out, imply
/// the same grid frequency second by second, and sit within 0.2 Hz of nominal. A fan or engine fails one of those.
pub fn detect_enf(x: &[f32], sr: f64) -> Enf {
    let (y, fa) = to_8k(x, sr);
    let n = nearest_pow2(8.0 * fa); // about 8 s: 0.12 Hz bins
    let hop = fa.round() as usize; // 1 s
    if y.len() < 4 * n {
        return Enf::default();
    }
    let sp = stft_mag(&y, fa, n, hop, 260.0);
    let p = |t: usize, k: usize| (sp.s[t * sp.nk + k] as f64).powi(2) + 1e-30;
    let freq = |k: usize| k as f64 * sp.df;
    let mut best = Enf::default();
    for nominal in [50u32, 60] {
        let mut strong = Vec::new();
        let mut tracks: Vec<Vec<f64>> = Vec::new();
        let mut dbs = Vec::new();
        for h in 1..=4u32 {
            let fc = (nominal * h) as f64;
            let on: Vec<usize> = (0..sp.nk).filter(|&k| (freq(k) - fc).abs() < 0.6).collect();
            let side: Vec<usize> = (0..sp.nk).filter(|&k| ((freq(k) - fc).abs() > 1.0) && ((freq(k) - fc).abs() < 3.0)).collect();
            if on.is_empty() || side.is_empty() {
                continue;
            }
            let mut on_max: Vec<f64> = (0..sp.nt).map(|t| on.iter().map(|&k| p(t, k)).fold(0.0, f64::max)).collect();
            let mut side_all: Vec<f64> = (0..sp.nt).flat_map(|t| side.iter().map(move |&k| (t, k))).map(|(t, k)| p(t, k)).collect();
            let snr = 10.0 * (median(&mut on_max) / median(&mut side_all)).log10();
            if snr >= 8.0 {
                strong.push(h);
                dbs.push(snr);
                // the line's frequency per frame (parabolic on log power), divided by the harmonic number
                let band: Vec<usize> = (0..sp.nk).filter(|&k| (freq(k) - fc).abs() < 0.5).collect();
                let tr: Vec<f64> = (0..sp.nt)
                    .map(|t| {
                        let mut j = band.iter().enumerate().max_by(|a, b| p(t, *a.1).total_cmp(&p(t, *b.1))).unwrap().0;
                        j = j.clamp(1, band.len() - 2);
                        let (y0, y1, y2) = (p(t, band[j - 1]).ln(), p(t, band[j]).ln(), p(t, band[j + 1]).ln());
                        let den = y0 - 2.0 * y1 + y2;
                        let d = if den.abs() > 1e-12 { 0.5 * (y0 - y2) / den } else { 0.0 };
                        (freq(band[j]) + d.clamp(-0.5, 0.5) * sp.df) / h as f64
                    })
                    .collect();
                tracks.push(tr);
            }
        }
        if strong.len() < 2 {
            continue;
        }
        // agreement: per harmonic, the median distance from the per-frame median of all harmonics
        let per_frame_med: Vec<f64> = (0..sp.nt).map(|t| median(&mut tracks.iter().map(|tr| tr[t]).collect::<Vec<_>>())).collect();
        let mut agree: Vec<f64> =
            tracks.iter().map(|tr| median(&mut tr.iter().zip(&per_frame_med).map(|(a, m)| (a - m).abs()).collect::<Vec<_>>())).collect();
        let mut all: Vec<f64> = tracks.iter().flatten().copied().collect();
        let grid = median(&mut all);
        if median(&mut agree) > 0.02 || (grid - nominal as f64).abs() > 0.2 {
            continue;
        }
        let top = (0..strong.len()).max_by(|&a, &b| dbs[a].total_cmp(&dbs[b])).unwrap();
        let tr = &tracks[top];
        let mean = tr.iter().sum::<f64>() / tr.len() as f64;
        let wander = (tr.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / tr.len() as f64).sqrt();
        let res = Enf {
            present: true,
            nominal_hz: nominal,
            lines: strong.iter().zip(&dbs).map(|(h, d)| (nominal * h, *d)).collect(),
            grid_hz: grid,
            wander_hz: wander,
        };
        let sum = |e: &Enf| e.lines.iter().map(|l| l.1).sum::<f64>();
        if !best.present || sum(&res) > sum(&best) {
            best = res;
        }
    }
    best
}

/// A long, gliding narrowband ridge (aircraft-like).
#[derive(Clone, Debug)]
pub struct RidgeInfo {
    pub t_start: f64,
    pub t_end: f64,
    pub f_start: f64,
    pub f_end: f64,
    pub strength_db: f64,
}

/// Long gliding ridges, strongest first: at least `min_s` seconds, `min_db` above the floor, changing frequency by
/// `min_glide` (a fraction) end to end, so steady hum and machines do not count.
pub fn detect_ridges(x: &[f32], sr: f64, cfg: &Config, min_db: f32, min_s: f64, min_glide: f64) -> Vec<RidgeInfo> {
    let (y, fa) = to_8k(x, sr);
    let n = nearest_pow2(fa);
    let hop = n / 4;
    let sp = stft_mag(&y, fa, n, hop, (cfg.band.1 as f64 + 200.0).min(fa / 2.0));
    if sp.nt == 0 {
        return Vec::new();
    }
    let s = Shape { nt: sp.nt, nb: sp.nk };
    let nf = (((cfg.floor_freq_hz as f64 / sp.df).round() as usize) | 1).max(3);
    let ntf = (((cfg.floor_time_s as f64 / sp.dt).round() as usize) | 1).max(1);
    let logm: Vec<f32> = sp.s.iter().map(|m| (m + 1e-12).ln()).collect();
    let mut med = vec![0.0; logm.len()];
    nd::median_freq(&logm, s, nf, &mut med);
    let mut fl = vec![0.0; logm.len()];
    nd::uniform_time(&med, s, ntf, &mut fl);
    let freq = |k: usize| k as f64 * sp.df;
    let inband = |k: usize| freq(k) >= cfg.band.0 as f64 && freq(k) <= cfg.band.1 as f64;
    let r: Vec<f32> =
        (0..logm.len()).map(|i| if inband(i % s.nb) { 20.0 / std::f32::consts::LN_10 * (logm[i] - fl[i]) } else { -99.0 }).collect();
    let mut peak = vec![false; r.len()];
    for t in 0..s.nt {
        for k in 0..s.nb {
            let i = t * s.nb + k;
            let l = r[t * s.nb + k.saturating_sub(1)];
            let h = r[t * s.nb + (k + 1).min(s.nb - 1)];
            peak[i] = r[i] > min_db && r[i] >= l && r[i] >= h;
        }
    }
    let max_bins = ((5.0 * sp.dt / sp.df).ceil() as usize).max(1);
    let closed = nd::close_time(&peak, s, 5);
    let bridged: Vec<bool> = peak.iter().zip(&closed).map(|(a, b)| *a || *b).collect();
    let bridged = nd::dilate(&bridged, s, max_bins, 0);
    let (lab, boxes) = nd::label(&bridged, s, 1, 1);
    let mut out = Vec::new();
    for (i, b) in boxes.iter().enumerate() {
        let id = i as u32 + 1;
        if ((b.t1 - b.t0 + 1) as f64) * sp.dt < min_s {
            continue;
        }
        let mut fr = Vec::new();
        let mut cols = Vec::new();
        let mut strengths = Vec::new();
        for t in b.t0..=b.t1 {
            let (mut wsum, mut fsum) = (0.0f64, 0.0f64);
            for k in b.k0..=b.k1 {
                let q = t * s.nb + k;
                if lab[q] == id && peak[q] {
                    let m = sp.s[q] as f64;
                    wsum += m;
                    fsum += m * freq(k);
                    strengths.push(r[q] as f64);
                }
            }
            if wsum > 0.0 {
                fr.push(fsum / wsum);
                cols.push(t);
            }
        }
        if (cols.len() as f64) * sp.dt < 0.6 * min_s {
            continue;
        }
        let k = (cols.len() / 10).max(3).min(cols.len());
        let f0 = median(&mut fr[..k].to_vec());
        let f1 = median(&mut fr[fr.len() - k..].to_vec());
        if (f1 - f0).abs() < min_glide * (f0 + f1) / 2.0 {
            continue;
        }
        out.push(RidgeInfo {
            t_start: cols[0] as f64 * sp.dt,
            t_end: *cols.last().unwrap() as f64 * sp.dt,
            f_start: f0,
            f_end: f1,
            strength_db: median(&mut strengths),
        });
    }
    out.sort_by(|a, b| b.strength_db.total_cmp(&a.strength_db));
    out
}
