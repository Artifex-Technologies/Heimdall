//! Flight tracks in local metres, propagation delay and Doppler (port of flyover-scrub's physics.py, MIT).
//!
//! The one subtle point, and the one that makes the attack work: the pitch heard at reception time t_r is set by the
//! aircraft's radial velocity at the emission time t_e, where t_r = t_e + |p(t_e) - o| / c. Evaluating it at t_r instead
//! gives a curve that is not just delayed but the wrong shape.

use heimdall_scrub::rng::Rng;

/// Speed of sound in m/s (about 20 C).
pub const SPEED_OF_SOUND: f64 = 343.0;

/// A sampled path: times (s, any epoch shared with the recording) and positions (east, north, up; metres from the
/// observer frame's origin).
#[derive(Clone, Debug, Default)]
pub struct Track {
    pub t: Vec<f64>,
    pub pos: Vec<[f64; 3]>,
}

fn interp(xs: &[f64], ys: &[f64], x: f64) -> f64 {
    if x <= xs[0] {
        return ys[0];
    }
    let n = xs.len();
    if x >= xs[n - 1] {
        return ys[n - 1];
    }
    let i = xs.partition_point(|&v| v <= x) - 1;
    let f = (x - xs[i]) / (xs[i + 1] - xs[i]);
    ys[i] + f * (ys[i + 1] - ys[i])
}

impl Track {
    /// Positions at new times (linear).
    pub fn resample(&self, t_new: &[f64]) -> Track {
        let col = |c: usize| self.pos.iter().map(|p| p[c]).collect::<Vec<_>>();
        let (x, y, z) = (col(0), col(1), col(2));
        Track {
            t: t_new.to_vec(),
            pos: t_new.iter().map(|&t| [interp(&self.t, &x, t), interp(&self.t, &y, t), interp(&self.t, &z, t)]).collect(),
        }
    }

    /// A smooth synthetic track with an optional constant-rate turn (heading: maths angle from east, degrees). Real
    /// aircraft are never quite straight and level; the turn is what makes a curve specific to one place.
    #[allow(clippy::too_many_arguments)]
    pub fn synthetic(
        t0: f64,
        duration: f64,
        start_xy: (f64, f64),
        altitude: f64,
        speed: f64,
        heading_deg: f64,
        turn_rate_deg_s: f64,
        turn_start: f64,
        turn_duration: f64,
    ) -> Track {
        let dt = 0.05;
        let n = (duration / dt).round() as usize + 1;
        let mut t = Vec::with_capacity(n);
        let mut pos = Vec::with_capacity(n);
        let (mut x, mut y) = start_xy;
        let mut prev_v: Option<(f64, f64)> = None;
        for i in 0..n {
            let tau = i as f64 * dt;
            let turned = turn_rate_deg_s * (tau - turn_start).clamp(0.0, turn_duration);
            let hd = (heading_deg + turned).to_radians();
            let v = (speed * hd.cos(), speed * hd.sin());
            if let Some(pv) = prev_v {
                x += 0.5 * (v.0 + pv.0) * dt;
                y += 0.5 * (v.1 + pv.1) * dt;
            }
            prev_v = Some(v);
            t.push(t0 + tau);
            pos.push([x, y, altitude]);
        }
        Track { t, pos }
    }
}

/// Per track sample, for one observer: (reception time, Doppler factor g, range). The heard frequency is f0 * g.
pub fn emission_geometry(track: &Track, obs: [f64; 3]) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let n = track.t.len();
    let r: Vec<f64> =
        track.pos.iter().map(|p| ((p[0] - obs[0]).powi(2) + (p[1] - obs[1]).powi(2) + (p[2] - obs[2]).powi(2)).sqrt()).collect();
    let t_rec: Vec<f64> = track.t.iter().zip(&r).map(|(t, r)| t + r / SPEED_OF_SOUND).collect();
    // numpy.gradient: central differences inside, one-sided at the ends
    let g = (0..n)
        .map(|i| {
            let vr = if n < 2 {
                0.0
            } else if i == 0 {
                (r[1] - r[0]) / (track.t[1] - track.t[0])
            } else if i == n - 1 {
                (r[n - 1] - r[n - 2]) / (track.t[n - 1] - track.t[n - 2])
            } else {
                (r[i + 1] - r[i - 1]) / (track.t[i + 1] - track.t[i - 1])
            };
            1.0 / (1.0 + vr / SPEED_OF_SOUND)
        })
        .collect();
    (t_rec, g, r)
}

/// The Doppler geometry of one track and observer, ready to be asked at many reception times.
pub struct Heard {
    t_rec: Vec<f64>,
    g: Vec<f64>,
    r: Vec<f64>,
    t_emit: Vec<f64>,
}

impl Heard {
    pub fn new(track: &Track, obs: [f64; 3]) -> Heard {
        let (t_rec, g, r) = emission_geometry(track, obs);
        Heard { t_rec, g, r, t_emit: track.t.clone() }
    }

    /// (Doppler factor, range, emission time) as heard at reception time `t_r`; `None` outside the track's span.
    pub fn at(&self, t_r: f64) -> Option<(f64, f64, f64)> {
        let n = self.t_rec.len();
        if n < 2 || t_r < self.t_rec[0] || t_r > self.t_rec[n - 1] {
            return None;
        }
        let i = (self.t_rec.partition_point(|&v| v <= t_r).max(1) - 1).min(n - 2);
        let f = (t_r - self.t_rec[i]) / (self.t_rec[i + 1] - self.t_rec[i]);
        let l = |v: &[f64]| v[i] + f * (v[i + 1] - v[i]);
        Some((l(&self.g), l(&self.r), l(&self.t_emit)))
    }
}

/// A physically modelled propeller flyover as heard at `obs`, for tests and calibration: the received waveform is
/// sin(2 pi k f0 t_e(t_r)), so Doppler and retardation come for free; amplitude falls as 1/r and is normalised to a peak of
/// about 1. Broadband engine noise (60-900 Hz) is added at `broadband`.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_flyover(
    track: &Track,
    obs: [f64; 3],
    t_start: f64,
    n: usize,
    sr: f64,
    f0: f64,
    harmonics: &[f64],
    broadband: f64,
    rng: &mut Rng,
) -> Vec<f32> {
    let heard = Heard::new(track, obs);
    let mut te = vec![0.0f64; n];
    let mut amp = vec![0.0f64; n];
    for i in 0..n {
        if let Some((_, r, t_e)) = heard.at(t_start + i as f64 / sr) {
            te[i] = t_e;
            amp[i] = 1.0 / r.max(1.0);
        }
    }
    let amax = amp.iter().cloned().fold(0.0, f64::max);
    if amax > 0.0 {
        amp.iter_mut().for_each(|a| *a /= amax);
    }
    let ph0 = rng.uniform() * std::f64::consts::TAU;
    let mut phase = 0.0f64;
    let mut sig = vec![0.0f64; n];
    let phases: Vec<f64> = harmonics.iter().map(|_| rng.uniform() * std::f64::consts::TAU).collect();
    for i in 0..n {
        let dte = if i + 1 < n && i > 0 { (te[i + 1] - te[i - 1]) / 2.0 } else { 0.0 };
        // slow blade-rate wander so it is not a perfect synthetic tone
        let wander = 1.0 + 0.002 * (2.0 * std::f64::consts::PI * 0.07 * te[i] + ph0).sin();
        phase += 2.0 * std::f64::consts::PI * f0 * dte * wander;
        for (k, a) in harmonics.iter().enumerate() {
            sig[i] += a * ((k + 1) as f64 * phase + phases[k]).sin();
        }
    }
    if broadband > 0.0 {
        // two-pole band-pass 60-900 Hz on white noise (a light stand-in for the reference's Butterworth)
        let (mut hp_x1, mut hp_y1) = (0.0f64, 0.0f64);
        let mut lp = 0.0f64;
        let a_hp = (-2.0 * std::f64::consts::PI * 60.0 / sr).exp();
        let a_lp = (-2.0 * std::f64::consts::PI * 900.0 / sr).exp();
        for s in sig.iter_mut() {
            let w = rng.normal() as f64;
            let hp = a_hp * (hp_y1 + w - hp_x1);
            hp_x1 = w;
            hp_y1 = hp;
            lp = a_lp * lp + (1.0 - a_lp) * hp;
            *s += broadband * 3.0 * lp;
        }
    }
    sig.iter().zip(&amp).map(|(s, a)| (s * a) as f32).collect()
}

/// What an attacker actually gets from ADS-B: positions about once a second with metre-scale noise.
pub fn degrade_like_adsb(track: &Track, rng: &mut Rng, period: f64, pos_sigma: f64) -> Track {
    let n = ((track.t[track.t.len() - 1] - track.t[0]) / period).floor() as usize;
    let ts: Vec<f64> = (0..n).map(|i| track.t[0] + i as f64 * period).collect();
    let mut s = track.resample(&ts);
    for p in s.pos.iter_mut() {
        p[0] += rng.normal() as f64 * pos_sigma;
        p[1] += rng.normal() as f64 * pos_sigma;
        p[2] += rng.normal() as f64 * pos_sigma * 0.5;
    }
    s
}
