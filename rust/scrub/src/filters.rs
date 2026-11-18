//! Time-domain building blocks of the live scrub: a biquad, the band replacer (a notch that removes a narrow band and the
//! matching band-pass that fills the hole with noise at the room's level), and the decimator that feeds the slow analysis.

/// A second-order section, direct form I, in f64: the hum notches sit a hertz wide at 50 Hz in a 48 kHz stream, with poles
/// a ten-thousandth inside the unit circle, where f32 coefficients would be too coarse.
#[derive(Clone, Copy, Default)]
pub struct Biquad {
    b0: f64,
    b1: f64,
    b2: f64,
    a1: f64,
    a2: f64,
    x1: f64,
    x2: f64,
    y1: f64,
    y2: f64,
}

impl Biquad {
    /// New coefficients; the state is kept, so a slowly moving notch glides without a click.
    pub fn set(&mut self, b: [f64; 3], a: [f64; 2]) {
        (self.b0, self.b1, self.b2, self.a1, self.a2) = (b[0], b[1], b[2], a[0], a[1]);
    }

    #[inline]
    pub fn run(&mut self, x: f64) -> f64 {
        let y = self.b0 * x + self.b1 * self.x1 + self.b2 * self.x2 - self.a1 * self.y1 - self.a2 * self.y2;
        self.x2 = self.x1;
        self.x1 = x;
        self.y2 = self.y1;
        // flush denormals: a silent input must not slow the real-time thread down
        self.y1 = if y.abs() < 1e-30 { 0.0 } else { y };
        y
    }

    pub fn reset(&mut self) {
        (self.x1, self.x2, self.y1, self.y2) = (0.0, 0.0, 0.0, 0.0);
    }
}

/// Coefficients of the allpass-based notch and its exact complement (Regalia and Mitra): with A(z) the second-order
/// allpass, notch = (1 + A) / 2 and band-pass = (1 - A) / 2, so notch + band-pass = 1. `bw_hz` is the -3 dB width.
fn notch_pair(f_hz: f64, bw_hz: f64, sr: f64) -> ([f64; 3], [f64; 3], [f64; 2]) {
    let r = (-std::f64::consts::PI * bw_hz / sr).exp();
    let w0 = 2.0 * std::f64::consts::PI * f_hz / sr;
    // the allpass reaches -pi where cos w = 2 r c / (1 + r^2): choose c so that is exactly w0
    let c = (w0.cos() * (1.0 + r * r) / (2.0 * r)).clamp(-1.0, 1.0);
    let a = [-2.0 * r * c, r * r];
    let g = (1.0 + r * r) / 2.0;
    let h = (1.0 - r * r) / 2.0;
    ([g, -2.0 * r * c, g], [h, 0.0, -h], a)
}

/// Removes one narrow band and puts noise at the background's level in its place, so neither the tone nor a hole shaped
/// like it is left. Two notches in a row (depth); one band-pass for the fill.
#[derive(Clone, Copy, Default)]
pub struct BandReplacer {
    n1: Biquad,
    n2: Biquad,
    fill: Biquad,
    /// standard deviation of the white noise fed to the band-pass (0 = remove only)
    noise_sd: f64,
    pub active: bool,
    pub f_hz: f64,
}

impl BandReplacer {
    /// Centre `f_hz`, -3 dB width `bw_hz`; the white noise into the fill has standard deviation `noise_sd`.
    pub fn set(&mut self, f_hz: f64, bw_hz: f64, sr: f64, noise_sd: f64) {
        let (notch, bp, a) = notch_pair(f_hz, bw_hz, sr);
        self.n1.set(notch, a);
        self.n2.set(notch, a);
        self.fill.set(bp, a);
        self.noise_sd = noise_sd;
        self.f_hz = f_hz;
        if !self.active {
            self.n1.reset();
            self.n2.reset();
            self.fill.reset();
            self.active = true;
        }
    }

    /// One sample; `white` is a standard normal draw shared by every replacer (disjoint bands of one white noise are
    /// uncorrelated, and one draw a sample is what a Raspberry Pi can afford).
    #[inline]
    pub fn run(&mut self, x: f64, white: f64) -> f64 {
        let y = self.n2.run(self.n1.run(x));
        y + self.fill.run(white * self.noise_sd)
    }
}

/// An FIR low-pass and decimation by an integer factor (Blackman-windowed sinc, unity gain at DC).
pub struct Decimator {
    factor: usize,
    taps: Vec<f32>,
    hist: Vec<f32>,
    pos: usize,
    phase: usize,
}

impl Decimator {
    pub fn new(factor: usize) -> Decimator {
        let factor = factor.max(1);
        let len = 16 * factor + 1;
        let fc = 0.45 / factor as f64; // cycles per input sample: 0.45 of the new Nyquist... of the new rate
        let mid = (len - 1) as f64 / 2.0;
        let mut taps: Vec<f64> = (0..len)
            .map(|i| {
                let x = i as f64 - mid;
                let sinc = if x == 0.0 { 2.0 * fc } else { (2.0 * std::f64::consts::PI * fc * x).sin() / (std::f64::consts::PI * x) };
                let t = 2.0 * std::f64::consts::PI * i as f64 / (len - 1) as f64;
                sinc * (0.42 - 0.5 * t.cos() + 0.08 * (2.0 * t).cos())
            })
            .collect();
        let s: f64 = taps.iter().sum();
        taps.iter_mut().for_each(|t| *t /= s);
        Decimator { factor, taps: taps.into_iter().map(|t| t as f32).collect(), hist: vec![0.0; len], pos: 0, phase: 0 }
    }

    pub fn factor(&self) -> usize {
        self.factor
    }

    /// Forget the past (no allocation: the voice disguise restarts its pitch tracker on PipeWire's real-time thread).
    pub fn reset(&mut self) {
        self.hist.iter_mut().for_each(|v| *v = 0.0);
        self.pos = 0;
        self.phase = 0;
    }

    /// Feed one sample; every `factor`-th call returns an output sample.
    #[inline]
    pub fn push(&mut self, x: f32) -> Option<f32> {
        let len = self.hist.len();
        self.hist[self.pos] = x;
        self.pos = (self.pos + 1) % len;
        self.phase += 1;
        if self.phase < self.factor {
            return None;
        }
        self.phase = 0;
        if self.factor == 1 {
            return Some(x);
        }
        let mut acc = 0.0f32;
        // hist[pos] is the oldest sample
        let (old, new) = self.hist.split_at(self.pos);
        let (t1, t2) = self.taps.split_at(new.len());
        for (a, b) in new.iter().zip(t1) {
            acc += a * b;
        }
        for (a, b) in old.iter().zip(t2) {
            acc += a * b;
        }
        Some(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone_gain(mut f: impl FnMut(f64) -> f64, hz: f64, sr: f64) -> f64 {
        let n = (sr * 4.0) as usize;
        let (mut pin, mut pout) = (0.0, 0.0);
        for i in 0..n {
            let x = (2.0 * std::f64::consts::PI * hz * i as f64 / sr).sin();
            let y = f(x);
            if i > n / 2 {
                pin += x * x;
                pout += y * y;
            }
        }
        10.0 * (pout / pin).log10()
    }

    #[test]
    fn replacer_removes_its_band_and_passes_the_rest() {
        let sr = 48000.0;
        let mut r = BandReplacer::default();
        r.set(120.0, 2.0, sr, 0.0);
        assert!(tone_gain(|x| r.run(x, 0.0), 120.0, sr) < -60.0);
        let mut r = BandReplacer::default();
        r.set(120.0, 2.0, sr, 0.0);
        assert!(tone_gain(|x| r.run(x, 0.0), 120.4, sr) < -10.0);
        let mut r = BandReplacer::default();
        r.set(120.0, 2.0, sr, 0.0);
        assert!(tone_gain(|x| r.run(x, 0.0), 300.0, sr).abs() < 0.05);
    }

    #[test]
    fn decimator_passes_low_and_stops_high() {
        let mut d = Decimator::new(6);
        let (mut lo, mut hi) = (0.0f32, 0.0f32);
        let mut d2 = Decimator::new(6);
        for i in 0..48000 {
            let t = i as f32 / 48000.0;
            if let Some(y) = d.push((2.0 * std::f32::consts::PI * 1000.0 * t).sin()) {
                if i > 4800 {
                    lo = lo.max(y.abs());
                }
            }
            if let Some(y) = d2.push((2.0 * std::f32::consts::PI * 7000.0 * t).sin()) {
                if i > 4800 {
                    hi = hi.max(y.abs());
                }
            }
        }
        assert!((lo - 1.0).abs() < 0.02, "{lo}");
        assert!(hi < 0.01, "{hi}");
    }
}
