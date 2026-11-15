//! The defence measured against the attack, on synthetic audio only: a physically modelled propeller flyover (Doppler with
//! emission-time geometry and a gentle turn), a speech-like voice, room noise and wandering 60 Hz mains hum.
//!
//! For each mode (whole-file and live) the tests show:
//! - the brightness scorer finds the true place in the raw mix, and after scrubbing scores it like a recording with no
//!   aircraft at all, with no "signal above chance" left;
//! - the trace-and-fit attack has no line left to follow (or it fits backwards as well as forwards);
//! - the mains hum (ENF) is no longer detected;
//! - the voice is essentially unchanged above 300 Hz, and everything above 2 kHz is untouched.
//!
//! Run with `--nocapture` to see the numbers.

#![allow(clippy::needless_range_loop)]

use flyover_attack::physics::{synthesize_flyover, Track};
use flyover_attack::scorer::{grid, score_candidates, strength_vs_chance, whitened_spectrogram, Scored, Sweep};
use flyover_attack::trace::{locate_trace, reversal_ratio, trace_ridge};
use flyover_attack::Box2;
use heimdall_scrub::complex::C32;
use heimdall_scrub::detect::{detect_enf, to_8k};
use heimdall_scrub::fft::{hann, RealFft};
use heimdall_scrub::rng::Rng;
use heimdall_scrub::{live, offline, Config};

const SR: f64 = 48000.0;
const SECONDS: f64 = 80.0;
const T_START: f64 = 100.0;

fn track() -> Track {
    Track::synthetic(0.0, 260.0, (-9000.0, -400.0), 700.0, 70.0, 5.0, -1.0, 100.0, 25.0)
}

fn rms(x: &[f32]) -> f64 {
    (x.iter().map(|v| (*v as f64).powi(2)).sum::<f64>() / x.len() as f64).sqrt()
}

/// Parts of one synthetic scene, each at 48 kHz.
struct Scene {
    room: Vec<f32>,
    plane: Vec<f32>,
    voice: Vec<f32>,
    voice_on: Vec<bool>,
    hum: Vec<f32>,
}

fn scene(plane_db: f64, seed: u64) -> Scene {
    let n = (SECONDS * SR) as usize;
    let mut rng = Rng::seeded(seed);
    // room tone: white noise at -40 dBFS, gently tilted (one-pole low-pass mixed in)
    let mut lp = 0.0f32;
    let room: Vec<f32> = (0..n)
        .map(|_| {
            let w = rng.normal();
            lp = 0.98 * lp + 0.02 * w;
            0.01 * (0.7 * w + 2.0 * lp)
        })
        .collect();
    let mut plane =
        synthesize_flyover(&track(), [0.0; 3], T_START, n, SR, 90.0, &[1.0, 0.7, 0.45, 0.3, 0.2], 0.15, &mut Rng::seeded(seed + 1));
    let on: Vec<f32> = plane.iter().copied().filter(|v| *v != 0.0).collect();
    let k = (10f64.powf(plane_db / 20.0) * rms(&room) / rms(&on)) as f32;
    plane.iter_mut().for_each(|v| *v *= k);
    // a voice: syllables (about 4 a second, in phrases), the pitch drifting between 125 and 175 Hz with a glide in every
    // syllable (up to 160 Hz/s), 30 harmonics under three formant bumps; about -22 dBFS while talking
    let mut voice = vec![0.0f32; n];
    let mut voice_on = vec![false; n];
    let mut phase = 0.0f64;
    for i in 0..n {
        let t = i as f64 / SR;
        let phrase = ((t / 6.0).fract() < 0.7) as i32 as f64;
        let syl = (2.0 * std::f64::consts::PI * 2.1 * t).sin().max(0.0).powf(0.6) * phrase;
        let f0 = 150.0 + 25.0 * (2.0 * std::f64::consts::PI * 0.35 * t).sin() + 12.0 * (2.0 * std::f64::consts::PI * 2.1 * t + 1.0).sin();
        phase += 2.0 * std::f64::consts::PI * f0 / SR;
        if syl > 0.0 {
            let mut v = 0.0;
            for h in 1..=30 {
                let f = f0 * h as f64;
                if f > 7000.0 {
                    break;
                }
                let formants = [(600.0, 1.0), (1200.0, 0.6), (2600.0, 0.3)];
                let env: f64 = formants.iter().map(|(c, a)| a / (1.0 + ((f - c) / 250.0).powi(2))).sum::<f64>() + 0.02;
                v += env * (h as f64 * phase).sin();
            }
            voice[i] = (0.03 * syl * v) as f32;
            voice_on[i] = syl > 0.3;
        }
    }
    // mains hum: a 60 Hz grid wandering a few hundredths of a hertz, mostly second and fourth harmonics (transformers)
    let mut hp = 0.0f64;
    let hum: Vec<f32> = (0..n)
        .map(|i| {
            let t = i as f64 / SR;
            let f = 60.0 + 0.02 * (2.0 * std::f64::consts::PI * t / 37.0).sin() + 0.01 * (2.0 * std::f64::consts::PI * t / 11.0).sin();
            hp += 2.0 * std::f64::consts::PI * f / SR;
            (0.004 * hp.sin() + 0.006 * (2.0 * hp).sin() + 0.003 * (4.0 * hp).sin()) as f32
        })
        .collect();
    Scene { room, plane, voice, voice_on, hum }
}

fn mix(parts: &[&[f32]]) -> Vec<f32> {
    (0..parts[0].len()).map(|i| parts.iter().map(|p| p[i]).sum()).collect()
}

fn cfg(seed: u64) -> Config {
    Config { seed: Some(seed), ..Config::default() }
}

/// Candidate places: a 9 x 9 grid, 500 m apart, around the truth at the origin.
fn places() -> Vec<[f64; 3]> {
    grid((0.0, 0.0), 2000.0, 500.0, 0.0)
}

fn sweep() -> Sweep {
    Sweep { f0_range: (87.0, 93.0), f0_step: 0.25, offsets: (0..=16).map(|i| -2.0 + 0.25 * i as f64).collect(), n_harmonics: 3 }
}

struct Verdict {
    truth_score: f64,
    truth_rank: usize,
    strength: f64,
    /// the truth's score in standard deviations of all candidates' scores, from their median
    truth_z: f64,
}

fn attack(audio: &[f32]) -> Verdict {
    let (x8, sr8) = to_8k(audio, SR);
    let spec = whitened_spectrogram(&x8, sr8, 1.0, 0.25, 1200.0);
    let tracks = [track()];
    let cands = places();
    let found: Scored = score_candidates(&spec, &tracks, T_START, &cands, &sweep());
    let null = score_candidates(&spec.reversed(), &tracks, T_START, &cands, &sweep());
    let truth = cands.iter().position(|c| c[0] == 0.0 && c[1] == 0.0).unwrap();
    let rank = found.ranked().iter().position(|&i| i == truth).unwrap() + 1;
    let mut sorted = found.scores.clone();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let med = sorted[sorted.len() / 2];
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let sd = (sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / sorted.len() as f64).sqrt();
    Verdict {
        truth_score: found.scores[truth],
        truth_rank: rank,
        strength: strength_vs_chance(&found, &null),
        truth_z: (found.scores[truth] - med) / sd.max(1e-12),
    }
}

struct TraceVerdict {
    frames: usize,
    top_error_m: f64,
    reversal: f64,
}

fn trace_attack(audio: &[f32]) -> TraceVerdict {
    let (x8, sr8) = to_8k(audio, SR);
    let spec = whitened_spectrogram(&x8, sr8, 2.0, 0.25, 1200.0);
    let ridge = trace_ridge(&spec, (65.0, 110.0), None, 0.6, 2.5);
    if ridge.len() < 20 {
        return TraceVerdict { frames: ridge.len(), top_error_m: f64::NAN, reversal: f64::NAN };
    }
    let area = Box2 { center: (700.0, -500.0), half_width: 2500.0, coarse: 250.0, fine: 50.0, refine_top: 15 };
    let offsets: Vec<f64> = (0..=32).map(|i| -4.0 + 0.25 * i as f64).collect();
    let tr = track();
    let res = locate_trace(&ridge, &tr, T_START, &area, &offsets);
    let best = res.ranked()[0];
    let c = res.candidates[best];
    TraceVerdict {
        frames: ridge.len(),
        top_error_m: (c[0] * c[0] + c[1] * c[1]).sqrt(),
        reversal: reversal_ratio(&ridge, &tr, T_START, &res, &offsets),
    }
}

/// Band-limited copies through one STFT (bins whose centre lies in [lo, hi) Hz kept).
fn band(x: &[f32], lo: f64, hi: f64) -> Vec<f32> {
    let n = 4096;
    let h = n / 4;
    let w = hann(n);
    let mut fft = RealFft::new(n);
    let mut buf = vec![0.0f32; n];
    let mut bins = vec![C32::ZERO; n / 2 + 1];
    let mut out = vec![0.0f32; x.len() + n];
    let df = SR / n as f64;
    let mut s = 0;
    while s + n <= x.len() {
        for i in 0..n {
            buf[i] = x[s + i] * w[i];
        }
        fft.forward(&buf, &mut bins);
        for (k, b) in bins.iter_mut().enumerate() {
            let f = k as f64 * df;
            if f < lo || f >= hi {
                *b = C32::ZERO;
            }
        }
        fft.inverse(&bins, &mut buf);
        for i in 0..n {
            out[s + i] += buf[i] * w[i] / 1.5;
        }
        s += h;
    }
    out.truncate(x.len());
    out
}

/// Ratio of a reference's energy to the error's, in dB, over the samples where `mask` holds (edges left out).
fn snr_db(reference: &[f32], got: &[f32], mask: impl Fn(usize) -> bool) -> f64 {
    let (mut s, mut e) = (0.0f64, 0.0f64);
    for i in (SR as usize * 4)..reference.len() - SR as usize * 2 {
        if mask(i) {
            s += (reference[i] as f64).powi(2);
            e += ((got[i] - reference[i]) as f64).powi(2);
        }
    }
    10.0 * (s / e.max(1e-30)).log10()
}

enum Mode {
    Offline,
    Live,
}

fn run(mode: &Mode, x: &[f32], seed: u64) -> Vec<f32> {
    match mode {
        Mode::Offline => offline::scrub(x, SR, &cfg(seed)).0,
        Mode::Live => live::scrub_live(x, SR, &cfg(seed)).0,
    }
}

fn name(mode: &Mode) -> &'static str {
    match mode {
        Mode::Offline => "whole-file",
        Mode::Live => "live",
    }
}

fn defeats_the_scorer(mode: Mode) {
    for plane_db in [-28.0, -10.0] {
        let sc = scene(plane_db, 3);
        let control = mix(&[&sc.room, &sc.voice, &sc.hum]);
        let raw = mix(&[&sc.room, &sc.plane, &sc.voice, &sc.hum]);
        let scrubbed = run(&mode, &raw, 11);
        let ctrl = attack(&control);
        let a_raw = attack(&raw);
        let a_scr = attack(&scrubbed);
        let ctrl_scr = attack(&run(&mode, &control, 11));
        eprintln!(
            "[{}] flyover {plane_db} dB re room: brightness scorer, truth's score above the no-aircraft control: raw {:+.3} \
             (rank {}/81, z {:.1}, {:.1}x chance), scrubbed {:+.3} (rank {}/81, z {:.1}, {:.1}x chance); control {:.1}x chance, \
             scrubbed control {:.1}x",
            name(&mode),
            a_raw.truth_score - ctrl.truth_score,
            a_raw.truth_rank,
            a_raw.truth_z,
            a_raw.strength,
            a_scr.truth_score - ctrl_scr.truth_score,
            a_scr.truth_rank,
            a_scr.truth_z,
            a_scr.strength,
            ctrl.strength,
            ctrl_scr.strength,
        );
        // the attack works on the raw mix: the true place wins, far above chance
        assert_eq!(a_raw.truth_rank, 1);
        assert!(a_raw.strength >= 4.0);
        assert!(a_raw.truth_score - ctrl.truth_score > 0.3);
        // and after scrubbing the truth scores like a recording with no aircraft (at least 90 % of its lead gone; what is
        // left is within the spread between two noise fills), does not stand out among the places, and nothing stands
        // above chance
        let residual = a_scr.truth_score - ctrl_scr.truth_score;
        assert!(residual < 0.1 * (a_raw.truth_score - ctrl.truth_score), "residual {residual:.3}");
        assert!(a_scr.strength.is_nan() || a_scr.strength < 4.0, "strength {:.1}", a_scr.strength);
        assert!(a_scr.truth_z < 2.5, "the truth still stands out: z {:.1}", a_scr.truth_z);

        let t_raw = trace_attack(&raw);
        let t_scr = trace_attack(&scrubbed);
        eprintln!(
            "[{}] flyover {plane_db} dB: trace-fit raw {} frames, top guess {:.0} m off, reversal {:.1}; scrubbed {} frames, top \
             guess {:.0} m off, reversal {:.1}",
            name(&mode),
            t_raw.frames,
            t_raw.top_error_m,
            t_raw.reversal,
            t_scr.frames,
            t_scr.top_error_m,
            t_scr.reversal
        );
        let located = t_scr.frames >= 20 && t_scr.reversal >= 3.0 && t_scr.top_error_m <= 1000.0;
        assert!(!located, "trace-fit still locates the scrubbed audio");
    }
}

#[test]
fn whole_file_scrub_defeats_the_scorer() {
    defeats_the_scorer(Mode::Offline);
}

#[test]
fn live_scrub_defeats_the_scorer() {
    defeats_the_scorer(Mode::Live);
}

/// Power spectra of 2048-point Hann frames (hop 1024) of a signal, from 4 s in to 2 s before the end.
fn frames(s: &[f32]) -> Vec<Vec<f64>> {
    let n = 2048;
    let w = hann(n);
    let mut fft = RealFft::new(n);
    let mut buf = vec![0.0f32; n];
    let mut bins = vec![C32::ZERO; n / 2 + 1];
    let mut out = Vec::new();
    let mut t = SR as usize * 4;
    while t + n < s.len() - SR as usize * 2 {
        for i in 0..n {
            buf[i] = s[t + i] * w[i];
        }
        fft.forward(&buf, &mut bins);
        out.push(bins.iter().map(|b| b.norm_sqr() as f64).collect());
        t += n / 2;
    }
    out
}

fn level_db(s: &[f32], lo: f64, hi: f64) -> f64 {
    let b = band(s, lo, hi);
    10.0 * (b[SR as usize * 4..b.len() - SR as usize * 2].iter().map(|v| (*v as f64).powi(2)).sum::<f64>()).log10()
}

fn keeps_the_voice_and_removes_the_hum(mode: Mode) {
    let sc = scene(-28.0, 5);
    let x = mix(&[&sc.room, &sc.voice, &sc.hum]);
    let y = run(&mode, &x, 13);
    let enf_in = detect_enf(&x, SR);
    let enf_out = detect_enf(&y, SR);
    eprintln!("[{}] ENF before: {}", name(&mode), enf_in.describe());
    eprintln!("[{}] ENF after: {}", name(&mode), enf_out.describe());
    assert!(enf_in.present && enf_in.nominal_hz == 60);
    assert!(!enf_out.present);

    // above 2.2 kHz: the input sample for sample (every part, not only the voice)
    let hi_snr = snr_db(&band(&x, 2200.0, 24000.0), &band(&y, 2200.0, 24000.0), |_| true);
    // 300 Hz - 2 kHz: the voice against what the scrub changed there, while it talks
    let v_band = band(&sc.voice, 300.0, 2000.0);
    let mid_x = band(&x, 300.0, 2000.0);
    let mid_y = band(&y, 300.0, 2000.0);
    let changed: Vec<f32> = v_band.iter().zip(mid_y.iter().zip(&mid_x)).map(|(v, (b, a))| v + (b - a)).collect();
    let voice_snr = snr_db(&v_band, &changed, |i| sc.voice_on[i]);
    // the same in the time-frequency cells where the voice stands 20 dB over the room: its own parts
    let d: Vec<f32> = y.iter().zip(&x).map(|(a, b)| a - b).collect();
    let (vs, rs, ds) = (frames(&sc.voice), frames(&sc.room), frames(&d));
    let (k0, k1) = ((300.0 / (SR / 2048.0)) as usize, (2000.0 / (SR / 2048.0)) as usize);
    let (mut v, mut e) = (0.0, 0.0);
    for f in 0..vs.len() {
        for k in k0..k1 {
            if vs[f][k] > 100.0 * rs[f][k] {
                v += vs[f][k];
                e += ds[f][k];
            }
        }
    }
    let voice_cells = 10.0 * (v / e).log10();
    // the room tone alone keeps its level (it is re-synthesised, not removed)
    let yr = run(&mode, &sc.room, 13);
    let room_mid = level_db(&yr, 300.0, 2000.0) - level_db(&sc.room, 300.0, 2000.0);
    let room_low = level_db(&yr, 20.0, 300.0) - level_db(&sc.room, 20.0, 300.0);
    let low = level_db(&y, 20.0, 300.0) - level_db(&x, 20.0, 300.0);
    eprintln!(
        "[{}] quality: above 2.2 kHz signal-to-change {hi_snr:.1} dB; voice 300 Hz-2 kHz vs what changed there while talking \
         {voice_snr:.1} dB ({voice_cells:.1} dB where the voice is 20 dB over the room); room tone alone 300 Hz-2 kHz \
         {room_mid:+.2} dB, 20-300 Hz {room_low:+.2} dB; the whole mix 20-300 Hz {low:+.2} dB (hum removed)",
        name(&mode)
    );
    assert!(hi_snr > 60.0);
    assert!(voice_snr > 15.0);
    assert!(voice_cells > 18.0);
    assert!(room_mid.abs() < 1.5 && room_low.abs() < 1.5);
}

#[test]
fn whole_file_scrub_keeps_the_voice_and_removes_the_hum() {
    keeps_the_voice_and_removes_the_hum(Mode::Offline);
}

#[test]
fn live_scrub_keeps_the_voice_and_removes_the_hum() {
    keeps_the_voice_and_removes_the_hum(Mode::Live);
}
