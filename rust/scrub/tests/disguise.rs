//! The voice disguise, measured on synthetic voices (no recording of anyone): the fundamental moves by the preset's
//! amount, the formants move by the preset's ratio, the level and the length and timing are kept, block sizes change
//! nothing (so no block-boundary artefacts), sample-to-sample jumps stay bounded also while switching, and two sessions
//! differ. `--nocapture` prints the numbers quoted in docs/VOICE_DISGUISE.md.

#![allow(clippy::needless_range_loop)]

use heimdall_scrub::complex::C32;
use heimdall_scrub::disguise::{disguise_buffer, Disguise, FileStage, Options, Preset};
use heimdall_scrub::fft::{hann, RealFft};
use heimdall_scrub::rng::Rng;

const SR: f64 = 48000.0;
const FORMANTS: [(f64, f64); 3] = [(650.0, 80.0), (1700.0, 100.0), (2600.0, 140.0)];

/// A sung vowel: harmonics of `f0(t)` under three formant peaks with a -6 dB/octave source tilt, plus a little breath.
/// `on(t)` gates it into syllables.
fn voice(seconds: f64, f0: impl Fn(f64) -> f64, on: impl Fn(f64) -> bool, seed: u64) -> Vec<f32> {
    let n = (seconds * SR) as usize;
    let mut rng = Rng::seeded(seed);
    let mut ph = 0.0f64;
    let env = |f: f64| -> f64 { FORMANTS.iter().map(|&(c, b)| 1.0 / (1.0 + ((f - c) / b).powi(2))).sum::<f64>() + 0.02 };
    let mut gate = 0.0f64;
    (0..n)
        .map(|i| {
            let t = i as f64 / SR;
            let f = f0(t);
            ph += 2.0 * std::f64::consts::PI * f / SR;
            gate += ((on(t) as u8 as f64) - gate) * 0.004;
            let mut s = 0.0;
            let mut k = 1.0;
            while k * f < 5000.0 {
                s += env(k * f) / k * (k * ph).sin();
                k += 1.0;
            }
            (0.12 * gate * s + 0.002 * rng.normal() as f64) as f32
        })
        .collect()
}

/// The fundamental of a steady stretch: the first autocorrelation peak within 90 % of the highest, 60-450 Hz.
fn f0_of(x: &[f32]) -> f64 {
    let (lo, hi) = ((SR / 450.0) as usize, (SR / 60.0) as usize);
    let n = x.len() - hi - 1;
    let r: Vec<f64> =
        (0..=hi + 1).map(|tau| if tau < lo - 1 { 0.0 } else { (0..n).map(|i| x[i] as f64 * x[i + tau] as f64).sum::<f64>() }).collect();
    let best = (lo..=hi).map(|t| r[t]).fold(f64::MIN, f64::max);
    let mut t = lo;
    while t < hi && !(r[t] >= 0.9 * best && r[t] >= r[t - 1] && r[t] >= r[t + 1]) {
        t += 1;
    }
    let (a, b, c) = (r[t - 1], r[t], r[t + 1]);
    let shift = 0.5 * (a - c) / (a - 2.0 * b + c);
    SR / (t as f64 + shift)
}

/// The long-term spectrum (Welch, 4096 points), smoothed over +-100 Hz; returns (Hz per bin, power).
fn envelope(x: &[f32]) -> (f64, Vec<f64>) {
    let n = 4096;
    let mut fft = RealFft::new(n);
    let w = hann(n);
    let mut bins = vec![C32::ZERO; n / 2 + 1];
    let mut buf = vec![0.0f32; n];
    let mut p = vec![0.0f64; n / 2 + 1];
    for start in (0..x.len() - n).step_by(n / 2) {
        for i in 0..n {
            buf[i] = x[start + i] * w[i];
        }
        fft.forward(&buf, &mut bins);
        for k in 0..p.len() {
            p[k] += bins[k].norm_sqr() as f64;
        }
    }
    let df = SR / n as f64;
    let half = (100.0 / df) as usize;
    let sm: Vec<f64> = (0..p.len()).map(|k| p[k.saturating_sub(half)..(k + half + 1).min(p.len())].iter().sum::<f64>()).collect();
    (df, sm)
}

/// A formant's frequency: the power-weighted centre of the half-power region around the highest point between lo and hi.
fn peak_in(env: &(f64, Vec<f64>), lo: f64, hi: f64) -> f64 {
    let (df, p) = env;
    let (a, b) = ((lo / df) as usize, (hi / df) as usize);
    let k = (a..=b).max_by(|&i, &j| p[i].total_cmp(&p[j])).unwrap();
    let half = 0.5 * p[k];
    let (mut l, mut r) = (k, k);
    while l > a && p[l - 1] > half {
        l -= 1;
    }
    while r < b && p[r + 1] > half {
        r += 1;
    }
    let w: f64 = p[l..=r].iter().sum();
    (l..=r).map(|i| i as f64 * df * p[i]).sum::<f64>() / w
}

fn rms_db(x: &[f32]) -> f64 {
    10.0 * (x.iter().map(|v| (*v as f64).powi(2)).sum::<f64>() / x.len() as f64).log10()
}

fn fixed() -> Options {
    Options { seed: Some(3), vary: false }
}

#[test]
fn the_fundamental_moves_by_the_preset() {
    // steady 140 Hz with a slight 5 Hz vibrato (+-1 Hz)
    let x = voice(4.0, |t| 140.0 + (2.0 * std::f64::consts::PI * 5.0 * t).sin(), |_| true, 1);
    let f_in = f0_of(&x[48000..144000]);
    for p in Preset::ALL {
        let y = disguise_buffer(&x, SR, p, fixed());
        let f_out = f0_of(&y[48000..144000]);
        let ratio = f_out / f_in;
        let st = 12.0 * ratio.log2();
        eprintln!("{}: F0 {f_in:.1} -> {f_out:.1} Hz = {st:+.2} semitones (preset {:+.1})", p.name(), p.semitones());
        assert!((st - p.semitones()).abs() < 0.25, "{}: {st:+.2} semitones", p.name());
    }
}

#[test]
fn the_formants_move_by_the_preset() {
    // the pitch glides 100 -> 200 Hz so the harmonics sweep the whole envelope
    let x = voice(6.0, |t| 100.0 + 100.0 * t / 6.0, |_| true, 2);
    let e_in = envelope(&x);
    let (f1, f2) = (peak_in(&e_in, 400.0, 1000.0), peak_in(&e_in, 1300.0, 2300.0));
    assert!((f1 - 650.0).abs() < 40.0 && (f2 - 1700.0).abs() < 60.0, "input formants {f1} {f2}");
    for p in Preset::ALL {
        let y = disguise_buffer(&x, SR, p, fixed());
        let e = envelope(&y);
        let (g1, g2) = (peak_in(&e, 400.0, 1000.0), peak_in(&e, 1300.0, 2300.0));
        eprintln!(
            "{}: F1 {f1:.0} -> {g1:.0} Hz (x{:.3}), F2 {f2:.0} -> {g2:.0} Hz (x{:.3}); preset x{:.2}",
            p.name(),
            g1 / f1,
            g2 / f2,
            p.formant()
        );
        // F2 and above move by the preset's ratio. F1 moves 4-6 % further: a few harmonics define it, and the changed
        // pitch samples the scaled, window-smeared envelope there differently (a property of PSOLA, measured, not hidden)
        assert!((g2 / f2 / p.formant() - 1.0).abs() < 0.03, "{}: F2 {f2} -> {g2}", p.name());
        assert!((g1 / f1 / p.formant() - 1.0).abs() < 0.07, "{}: F1 {f1} -> {g1}", p.name());
        assert!((g1 / f1 - 1.0).signum() == (p.formant() - 1.0).signum());
    }
}

#[test]
fn level_length_and_timing_are_kept() {
    // syllables: 0.4 s on, 0.25 s off, pitch moving like speech
    let x = voice(8.0, |t| 130.0 + 25.0 * (2.0 * std::f64::consts::PI * 0.7 * t).sin(), |t| (t / 0.65).fract() < 0.6, 3);
    for p in Preset::ALL {
        let y = disguise_buffer(&x, SR, p, Options { seed: Some(5), vary: true });
        assert_eq!(y.len(), x.len());
        let d = rms_db(&y[24000..]) - rms_db(&x[24000..]);
        // timing: the 10 ms energy envelopes line up best within +-10 ms
        let env = |s: &[f32]| -> Vec<f64> { s.chunks(480).map(|c| c.iter().map(|v| (*v as f64).powi(2)).sum::<f64>()).collect() };
        let (ex, ey) = (env(&x), env(&y));
        let corr = |lag: i64| -> f64 { (5..ex.len() as i64 - 5).map(|i| ex[i as usize] * ey[(i + lag) as usize]).sum() };
        let best = (-4..=4).max_by(|&a, &b| corr(a).total_cmp(&corr(b))).unwrap();
        eprintln!("{}: level {d:+.2} dB, length {} = {}, envelope offset {} ms", p.name(), y.len(), x.len(), best * 10);
        assert!(d.abs() < 1.5, "{}: level {d:+.2} dB", p.name());
        assert!(best.abs() <= 1, "{}: offset {} ms", p.name(), best * 10);
    }
    // unvoiced: noise keeps its level too
    let mut rng = Rng::seeded(4);
    let noise: Vec<f32> = (0..96000).map(|_| 0.05 * rng.normal()).collect();
    for p in Preset::ALL {
        let y = disguise_buffer(&noise, SR, p, fixed());
        let d = rms_db(&y[4800..]) - rms_db(&noise[4800..]);
        eprintln!("{}: noise level {d:+.2} dB", p.name());
        assert!(d.abs() < 1.5);
    }
}

/// Max sample-to-sample step of the output against that of the input.
fn jump_ratio(x: &[f32], y: &[f32]) -> f64 {
    let step = |s: &[f32]| s.windows(2).map(|w| (w[1] - w[0]).abs()).fold(0.0f32, f32::max) as f64;
    step(y) / step(x)
}

#[test]
fn block_sizes_change_nothing_and_switching_does_not_click() {
    let x = voice(6.0, |t| 120.0 + 40.0 * (2.0 * std::f64::consts::PI * 0.5 * t).sin(), |t| (t / 0.5).fract() < 0.7, 6);
    // the same session driven in PipeWire-sized blocks and in odd ones, switching on, between presets and off
    let run = |sizes: &[usize]| -> Vec<f32> {
        let mut d = Disguise::new(SR, Options { seed: Some(9), vary: true });
        let mut y = vec![0.0f32; x.len()];
        let switches = [(30_000, Some(Preset::Lower)), (130_000, Some(Preset::Higher)), (230_000, None)];
        let (mut i, mut k) = (0, 0);
        while i < x.len() {
            let end = (i + sizes[k % sizes.len()]).min(x.len());
            k += 1;
            // switches at sample-exact places, whatever the blocks
            let mut j = i;
            for &(at, p) in &switches {
                if (i..end).contains(&at) {
                    d.process(&x[j..at], &mut y[j..at]);
                    j = at;
                    d.set_preset(p);
                }
            }
            d.process(&x[j..end], &mut y[j..end]);
            i = end;
        }
        y
    };
    let a = run(&[1024]);
    let b = run(&[1, 97, 256, 1500, 13, 4096, 480]);
    assert_eq!(a, b, "the output depends on the block sizes");
    let r = jump_ratio(&x, &a);
    eprintln!("largest sample-to-sample step: {r:.2}x the input's (switching on, lower -> higher, off)");
    assert!(r < 2.0, "{r}");
    // off again: the input exactly, once the fade is over
    assert_eq!(&a[232_000..], &x[232_000..]);
}

#[test]
fn the_file_stage_matches_the_buffer_and_keeps_the_length() {
    let x = voice(2.0, |_| 150.0, |_| true, 7);
    let opts = Options { seed: Some(2), vary: true };
    let want = disguise_buffer(&x, SR, Preset::Higher, opts);
    let mut st = FileStage::new(SR, Preset::Higher, opts);
    let mut got = Vec::new();
    for c in x.chunks(7000) {
        st.push(c, &mut got);
    }
    st.finish(&mut got);
    assert_eq!(got, want);
    // shorter than the delay
    let mut st = FileStage::new(SR, Preset::Lower, opts);
    let mut got = Vec::new();
    st.push(&x[..100], &mut got);
    st.finish(&mut got);
    assert_eq!(got.len(), 100);
}

#[test]
fn sessions_differ_and_the_jitter_stays_small() {
    let x = voice(12.0, |_| 140.0, |_| true, 8);
    let f_in = f0_of(&x[24000..72000]);
    let mut seen = Vec::new();
    for seed in [None, None, Some(11)] {
        let y = disguise_buffer(&x, SR, Preset::Lower, Options { seed, vary: true });
        let sts: Vec<f64> = (0..10).map(|s| 12.0 * (f0_of(&y[(s + 1) * 48000..(s + 1) * 48000 + 24000]) / f_in).log2()).collect();
        let lo = sts.iter().copied().fold(f64::MAX, f64::min);
        let hi = sts.iter().copied().fold(f64::MIN, f64::max);
        eprintln!("lower, seed {seed:?}: semitones over 10 s from {lo:+.2} to {hi:+.2}");
        // the preset's -3, the session's +-0.4 and the jitter's +-0.6 at most
        assert!(lo > -4.1 && hi < -1.9, "{lo} {hi}");
        seen.push(sts);
    }
    // two sessions seeded by the operating system are not the same transformation
    let diff = seen[0].iter().zip(&seen[1]).map(|(a, b)| (a - b).abs()).fold(0.0, f64::max);
    assert!(diff > 0.02, "{diff}");
    // and within one session the pitch wanders
    let spread = seen[2].iter().copied().fold(f64::MIN, f64::max) - seen[2].iter().copied().fold(f64::MAX, f64::min);
    assert!(spread > 0.05, "{spread}");
}

/// The private microphone's order: the live scrub, then the disguise. The scrub re-synthesises a voice's weak low bins
/// with noise, which makes its pitch harder to follow; the disguise must still move it.
#[test]
fn after_the_live_scrub_the_pitch_still_moves() {
    use heimdall_scrub::{live::Live, Config};
    // 137 Hz (off the mains harmonics) with an 8 Hz vibrato of +-10 Hz, in syllables, over room noise
    let x = voice(10.0, |t| 137.0 + 10.0 * (2.0 * std::f64::consts::PI * 8.0 * t).sin(), |t| (t / 0.4).fract() < 0.7, 9);
    let mut rng = Rng::seeded(10);
    let x: Vec<f32> = x.iter().map(|v| v + 0.004 * rng.normal()).collect();
    let mut live = Live::new(&Config { seed: Some(1), ..Config::default() }, SR);
    let mut scrubbed = vec![0.0f32; x.len()];
    for (i, o) in x.chunks(1024).zip(scrubbed.chunks_mut(1024)) {
        live.process(i, o);
    }
    let f_in = f0_of(&scrubbed[96000..]);
    for p in Preset::ALL {
        let y = disguise_buffer(&scrubbed, SR, p, fixed());
        let st = 12.0 * (f0_of(&y[96000..]) / f_in).log2();
        eprintln!("after the live scrub, {}: {st:+.2} semitones (preset {:+.1})", p.name(), p.semitones());
        assert!((st - p.semitones()).abs() < 0.6, "{}: {st:+.2}", p.name());
    }
}
