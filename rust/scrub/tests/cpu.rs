//! How much of one CPU core the scrub takes per channel at 48 kHz, on a busy input: room noise, a voice-like harmonic
//! signal, wandering 50 Hz hum with harmonics and two gliding tones (so the hum notches and the ridge notches are all at
//! work). Printed with `--nocapture`; the assertions only catch a gross regression (CI machines vary).
//!
//! `cargo test --release -p heimdall-scrub --test cpu -- --nocapture` gives the numbers quoted in docs/LOCATION_SOUNDS.md
//! and docs/VOICE_DISGUISE.md.

#![allow(clippy::needless_range_loop)]

use std::time::Instant;

use heimdall_scrub::disguise::{Disguise, Options, Preset};
use heimdall_scrub::rng::Rng;
use heimdall_scrub::{live::Live, offline::Offline, Config};

const SR: f64 = 48000.0;

fn busy_input(seconds: f64) -> Vec<f32> {
    let n = (seconds * SR) as usize;
    let mut rng = Rng::seeded(9);
    let (mut p1, mut p2, mut pv, mut ph) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    (0..n)
        .map(|i| {
            let t = i as f64 / SR;
            let g1 = 90.0 * (1.1 - 0.2 * (t / seconds));
            let g2 = 140.0 * (0.9 + 0.2 * (t / seconds));
            p1 += 2.0 * std::f64::consts::PI * g1 / SR;
            p2 += 2.0 * std::f64::consts::PI * g2 / SR;
            pv += 2.0 * std::f64::consts::PI * (150.0 + 20.0 * (2.0 * std::f64::consts::PI * 2.0 * t).sin()) / SR;
            ph += 2.0 * std::f64::consts::PI * (50.0 + 0.02 * (t / 7.0).sin()) / SR;
            let voice: f64 = (1..20).map(|k| (k as f64 * pv).sin() / k as f64).sum::<f64>() * ((2.0 * t).fract() < 0.6) as u8 as f64;
            let hum = ph.sin() + 0.7 * (2.0 * ph).sin() + 0.4 * (3.0 * ph).sin() + 0.3 * (6.0 * ph).sin();
            (0.01 * rng.normal() as f64 + 0.02 * voice + 0.01 * hum + 0.01 * (p1.sin() + 0.5 * (2.0 * p1).sin()) + 0.005 * p2.sin()) as f32
        })
        .collect()
}

#[test]
fn live_cpu_per_channel_at_48k() {
    let seconds = 60.0;
    let x = busy_input(seconds);
    let mut l = Live::new(&Config { seed: Some(1), ..Config::default() }, SR);
    let mut y = vec![0.0f32; x.len()];
    // PipeWire's default quantum at 48 kHz is 1024 samples
    let start = Instant::now();
    for (i, o) in x.chunks(1024).zip(y.chunks_mut(1024)) {
        l.process(i, o);
    }
    let cpu = start.elapsed().as_secs_f64();
    let frac = cpu / seconds;
    let rep = l.report();
    eprintln!(
        "live: {:.2} s for {seconds} s of audio = {:.2} % of one core per channel at 48 kHz; latency {} samples ({:.1} ms); \
         ridges confirmed {}, hum {} Hz",
        cpu,
        100.0 * frac,
        l.latency(),
        l.latency() as f64 / SR * 1000.0,
        rep.ridges_found,
        rep.hum_nominal_hz
    );
    assert!(frac < 0.5);
    assert!(l.latency() as f64 / SR <= 0.030);
}

/// The voice disguise after the live scrub, as the private microphone runs it with the disguise on: each preset alone,
/// then the two stages together.
#[test]
fn disguise_cpu_per_channel_at_48k() {
    let seconds = 60.0;
    let x = busy_input(seconds);
    let mut y = vec![0.0f32; x.len()];
    for p in Preset::ALL {
        let mut d = Disguise::new(SR, Options { seed: Some(1), vary: true });
        d.set_preset_now(Some(p));
        let start = Instant::now();
        for (i, o) in x.chunks(1024).zip(y.chunks_mut(1024)) {
            d.process(i, o);
        }
        let frac = start.elapsed().as_secs_f64() / seconds;
        eprintln!(
            "disguise {}: {:.2} % of one core per channel at 48 kHz; latency {} samples ({:.1} ms)",
            p.name(),
            100.0 * frac,
            d.latency(),
            d.latency() as f64 / SR * 1000.0
        );
        assert!(frac < 0.25);
        assert!(d.latency() as f64 / SR <= 0.035);
    }
    let mut l = Live::new(&Config { seed: Some(1), ..Config::default() }, SR);
    let mut d = Disguise::new(SR, Options { seed: Some(1), vary: true });
    d.set_preset_now(Some(Preset::Lower));
    let mut mid = vec![0.0f32; 1024];
    let start = Instant::now();
    for (i, o) in x.chunks(1024).zip(y.chunks_mut(1024)) {
        l.process(i, &mut mid[..i.len()]);
        d.process(&mid[..i.len()], o);
    }
    let frac = start.elapsed().as_secs_f64() / seconds;
    eprintln!(
        "scrub + disguise: {:.2} % of one core per channel at 48 kHz; latency {} samples ({:.1} ms)",
        100.0 * frac,
        l.latency() + d.latency(),
        (l.latency() + d.latency()) as f64 / SR * 1000.0
    );
    // off: a copy
    let mut d = Disguise::new(SR, Options::default());
    let start = Instant::now();
    for (i, o) in x.chunks(1024).zip(y.chunks_mut(1024)) {
        d.process(i, o);
    }
    eprintln!("disguise off: {:.3} % of one core", 100.0 * start.elapsed().as_secs_f64() / seconds);
}

#[test]
fn whole_file_speed_at_48k() {
    let seconds = 60.0;
    let x = busy_input(seconds);
    let start = Instant::now();
    let mut o = Offline::new(&Config { seed: Some(1), ..Config::default() }, SR);
    let mut y = Vec::new();
    for c in x.chunks(1 << 16) {
        o.push(c);
        o.pull(&mut y);
    }
    o.finish();
    o.pull(&mut y);
    let cpu = start.elapsed().as_secs_f64();
    assert_eq!(y.len(), x.len());
    eprintln!("whole-file: {:.2} s for {seconds} s of audio ({:.0}x real time) per channel at 48 kHz", cpu, seconds / cpu);
    assert!(cpu < seconds);
}
