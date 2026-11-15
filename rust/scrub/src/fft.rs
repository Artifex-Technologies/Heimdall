//! A small FFT of our own (radix 2, sizes that are powers of two), so the DSP needs no crate and runs the same on a
//! Raspberry Pi. The real transform packs N real samples into N/2 complex ones and untangles the result, half the work of a
//! complex transform of N.
//!
//! Every buffer is made in `new`; `forward` and `inverse` never allocate, so the live filter can call them from PipeWire's
//! real-time thread.

use crate::complex::C32;

/// A complex FFT of one size.
pub struct ComplexFft {
    n: usize,
    /// e^(-2 pi i k / n) for k < n/2, computed in f64 and stored as f32
    twiddles: Vec<C32>,
    /// the bit-reversed index of every position
    rev: Vec<u32>,
}

impl ComplexFft {
    /// A transform of `n` points; `n` must be a power of two (at least 2).
    pub fn new(n: usize) -> ComplexFft {
        assert!(n >= 2 && n.is_power_of_two(), "FFT size {n} is not a power of two");
        let twiddles = (0..n / 2)
            .map(|k| {
                let a = -2.0 * std::f64::consts::PI * k as f64 / n as f64;
                C32::new(a.cos() as f32, a.sin() as f32)
            })
            .collect();
        let bits = n.trailing_zeros();
        let rev = (0..n as u32).map(|i| i.reverse_bits() >> (32 - bits)).collect();
        ComplexFft { n, twiddles, rev }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// In place; unnormalised both ways (`inverse` = true conjugates the twiddles, the caller scales by 1/n).
    pub fn process(&self, buf: &mut [C32], inverse: bool) {
        let n = self.n;
        assert_eq!(buf.len(), n);
        for i in 0..n {
            let j = self.rev[i] as usize;
            if j > i {
                buf.swap(i, j);
            }
        }
        let mut size = 2;
        while size <= n {
            let half = size / 2;
            let step = n / size;
            for start in (0..n).step_by(size) {
                for j in 0..half {
                    let mut w = self.twiddles[j * step];
                    if inverse {
                        w = w.conj();
                    }
                    let a = buf[start + j];
                    let b = buf[start + j + half] * w;
                    buf[start + j] = a + b;
                    buf[start + j + half] = a - b;
                }
            }
            size *= 2;
        }
    }
}

/// A real FFT of `n` points: `n` samples in, `n/2 + 1` bins out (DC to Nyquist), and back.
pub struct RealFft {
    n: usize,
    half: ComplexFft,
    /// e^(-2 pi i k / n) for k <= n/2
    w: Vec<C32>,
    scratch: Vec<C32>,
}

impl RealFft {
    pub fn new(n: usize) -> RealFft {
        assert!(n >= 4 && n.is_power_of_two(), "real FFT size {n} is not a power of two of at least 4");
        let w = (0..=n / 2)
            .map(|k| {
                let a = -2.0 * std::f64::consts::PI * k as f64 / n as f64;
                C32::new(a.cos() as f32, a.sin() as f32)
            })
            .collect();
        RealFft { n, half: ComplexFft::new(n / 2), w, scratch: vec![C32::ZERO; n / 2] }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Bins of the unnormalised DFT: `out[k]` = sum x[t] e^(-2 pi i k t / n), k = 0..=n/2.
    pub fn forward(&mut self, input: &[f32], out: &mut [C32]) {
        let (n, m) = (self.n, self.n / 2);
        assert_eq!(input.len(), n);
        assert_eq!(out.len(), m + 1);
        for (k, z) in self.scratch.iter_mut().enumerate() {
            *z = C32::new(input[2 * k], input[2 * k + 1]);
        }
        self.half.process(&mut self.scratch, false);
        let z = &self.scratch;
        for k in 0..=m {
            let zk = z[k % m];
            let zr = z[(m - k) % m].conj();
            let e = (zk + zr).scale(0.5);
            // (zk - zr) / 2i
            let d = zk - zr;
            let o = C32::new(d.im * 0.5, -d.re * 0.5);
            out[k] = e + self.w[k] * o;
        }
    }

    /// The inverse of `forward`: `inverse(forward(x)) == x` (scaled by 1/n here).
    pub fn inverse(&mut self, bins: &[C32], out: &mut [f32]) {
        let (n, m) = (self.n, self.n / 2);
        assert_eq!(bins.len(), m + 1);
        assert_eq!(out.len(), n);
        for k in 0..m {
            let xk = bins[k];
            let xr = bins[m - k].conj();
            let e = (xk + xr).scale(0.5);
            let o = (xk - xr).scale(0.5) * self.w[k].conj();
            // Z = E + i O
            self.scratch[k] = C32::new(e.re - o.im, e.im + o.re);
        }
        self.half.process(&mut self.scratch, true);
        let s = 1.0 / m as f32;
        for (k, z) in self.scratch.iter().enumerate() {
            out[2 * k] = z.re * s;
            out[2 * k + 1] = z.im * s;
        }
    }
}

/// The periodic Hann window (scipy's `hann` for spectra): with a hop of a quarter window its squares sum to 1.5 everywhere,
/// so analysis and synthesis with it reconstruct exactly.
pub fn hann(n: usize) -> Vec<f32> {
    (0..n).map(|i| (0.5 - 0.5 * (2.0 * std::f64::consts::PI * i as f64 / n as f64).cos()) as f32).collect()
}

/// Amplitude for fresh noise put into replaced bins. Overlap-add of frames that agree (a real signal) gives back its
/// level; frames of independent random noise do not: with a Hann window and a quarter-window hop their sum has
/// mean(w^2) / sum-of-overlapping(w^2) = 0.375 / 1.5 = a quarter of the power the bins suggest. Without this the
/// re-synthesised room tone came out 6 dB too quiet (measured in the tests).
pub const INCOHERENT_GAIN: f32 = 2.0;

/// The power of two nearest to `x` on a log scale (at least 4).
pub fn nearest_pow2(x: f64) -> usize {
    let lo = (x.max(4.0).log2().floor() as u32).max(2);
    let (a, b) = (1usize << lo, 1usize << (lo + 1));
    if x / a as f64 <= b as f64 / x {
        a
    } else {
        b
    }
}

/// The largest power of two not above `x` (at least 4).
pub fn floor_pow2(x: f64) -> usize {
    1usize << (x.max(4.0).log2().floor() as u32).max(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dft(x: &[f32]) -> Vec<C32> {
        let n = x.len();
        (0..=n / 2)
            .map(|k| {
                let (mut re, mut im) = (0.0f64, 0.0f64);
                for (t, &v) in x.iter().enumerate() {
                    let a = -2.0 * std::f64::consts::PI * (k * t) as f64 / n as f64;
                    re += v as f64 * a.cos();
                    im += v as f64 * a.sin();
                }
                C32::new(re as f32, im as f32)
            })
            .collect()
    }

    #[test]
    fn real_fft_matches_the_dft_and_inverts() {
        for &n in &[4usize, 8, 64, 1024] {
            let x: Vec<f32> = (0..n).map(|i| ((i * 7919) % 101) as f32 / 50.0 - 1.0).collect();
            let mut f = RealFft::new(n);
            let mut bins = vec![C32::ZERO; n / 2 + 1];
            f.forward(&x, &mut bins);
            for (a, b) in bins.iter().zip(dft(&x)) {
                assert!((a.re - b.re).abs() < 1e-3 * n as f32 && (a.im - b.im).abs() < 1e-3 * n as f32, "n={n}");
            }
            let mut back = vec![0.0; n];
            f.inverse(&bins, &mut back);
            for (a, b) in back.iter().zip(&x) {
                assert!((a - b).abs() < 1e-4, "n={n}: {a} vs {b}");
            }
        }
    }

    #[test]
    fn hann_quarter_hop_sums_to_one_and_a_half() {
        let w = hann(64);
        for t in 0..16 {
            let s: f32 = (0..4).map(|k| w[t + 16 * k].powi(2)).sum();
            assert!((s - 1.5).abs() < 1e-5);
        }
    }

    #[test]
    fn nearest_power_of_two() {
        assert_eq!(nearest_pow2(12000.0), 16384);
        assert_eq!(nearest_pow2(11025.0), 8192);
        assert_eq!(nearest_pow2(4000.0), 4096);
        assert_eq!(nearest_pow2(1008.0), 1024);
    }
}
