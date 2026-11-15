//! The time-domain stage: the mains-hum notches (harmonics of 50 and 60 Hz up to `hum_max_hz`, following the grid's
//! drift) and, live, one notch per confirmed ridge. Each notch is a band replacer: the band is removed and refilled with
//! noise at the floor's level, so no line and no line-shaped hole is left.
//!
//! A hum notch is on only while its harmonic has stood above the floor most of the last two seconds (hum is there all the
//! time; a voice's harmonics only pass through), so a voice keeps its spectrum. Hum under the floor needs no notch: the
//! re-synthesis of the background replaces it.

use crate::analysis::{FineAnalyzer, NOMINALS};
use crate::config::Config;
use crate::filters::BandReplacer;
use crate::rng::Rng;

/// At most this many ridges are notched at once (the strongest); more than a handful at a time is rare outside music.
pub const MAX_RIDGES: usize = 12;
const MAX_HUM: usize = 48;

pub struct TimeStage {
    sr: f64,
    pub an: FineAnalyzer,
    hum: [(usize, f64, BandReplacer); MAX_HUM],
    n_hum: usize,
    ridges: [BandReplacer; MAX_RIDGES],
    slot_track: [Option<usize>; MAX_RIDGES],
    ridge_bw: f64,
    /// the highest hum harmonic notched (0 = none)
    hum_top: f64,
    /// seconds each hum notch stays on after its harmonic was last seen
    hum_hang: [f64; MAX_HUM],
    /// share of recent frames in which each harmonic stood above the floor
    hum_steady: [f64; MAX_HUM],
    rng: Rng,
    /// analysis frames in which each grid's hum was being notched
    pub hum_frames: [u64; 2],
}

impl TimeStage {
    pub fn new(cfg: &Config, sr: f64, track_ridges: bool, rng: Rng) -> TimeStage {
        let an = FineAnalyzer::new(cfg, sr, track_ridges);
        let mut hum = [(0usize, 0.0f64, BandReplacer::default()); MAX_HUM];
        let mut n_hum = 0;
        let mut hum_top = 0.0;
        if !cfg.keep_hum {
            let top = cfg.hum_max_hz.min(cfg.band.1).min((sr / 2.0 * 0.9) as f32) as f64;
            for (i, n) in NOMINALS.iter().enumerate() {
                let mut k = 1.0;
                while k * n <= top && n_hum < MAX_HUM {
                    hum[n_hum] = (i, k, BandReplacer::default());
                    hum_top = f64::max(hum_top, k * n + 2.0);
                    n_hum += 1;
                    k += 1.0;
                }
            }
        }
        let mut s = TimeStage {
            sr,
            an,
            hum,
            n_hum,
            ridges: [BandReplacer::default(); MAX_RIDGES],
            slot_track: [None; MAX_RIDGES],
            ridge_bw: 2.0 * cfg.ridge_pad_hz as f64,
            hum_top,
            hum_hang: [0.0; MAX_HUM],
            hum_steady: [0.0; MAX_HUM],
            rng,
            hum_frames: [0; 2],
        };
        s.retune();
        s
    }

    fn retune(&mut self) {
        let dt = self.an.frame_seconds();
        let a = (-dt / 2.0).exp();
        for ((h, hang), steady) in self.hum[..self.n_hum].iter_mut().zip(self.hum_hang.iter_mut()).zip(self.hum_steady.iter_mut()) {
            let (i, k) = (h.0, h.1);
            let f = k * self.an.hum.grid_hz(i);
            // A harmonic is notched while it has stood above the floor in most of the last two seconds (hum is there all
            // the time; a voice's harmonics only pass by), and for three seconds after. Elsewhere the band is left to the
            // re-synthesis, so the voice keeps its spectrum: notching every harmonic of 50 and 60 Hz whenever speech
            // crossed one cost the voice about 12 dB of signal-to-change in the tests.
            let above = (self.an.hum.present(i) && self.an.level_db_at(f) >= 3.0) as u8 as f64;
            *steady = a * *steady + (1.0 - a) * above;
            if *steady > 0.8 {
                *hang = 3.0;
            } else {
                *hang = (*hang - dt).max(0.0);
            }
            if *hang > 0.0 {
                let bw = (0.15 * k).max(1.5);
                let sd = self.an.noise_sd_at(f, self.sr);
                h.2.set(f, bw, self.sr, sd);
            } else {
                h.2.active = false;
            }
        }
        for i in 0..2 {
            self.hum_frames[i] += self.hum[..self.n_hum].iter().any(|h| h.0 == i && h.2.active) as u64;
        }
        let Some(tr) = self.an.ridges.as_ref() else { return };
        // drop slots whose ridge has ended
        for (slot, t) in self.slot_track.iter_mut().enumerate() {
            if let Some(ti) = *t {
                if !tr.tracks[ti].confirmed {
                    *t = None;
                    self.ridges[slot].active = false;
                }
            }
        }
        // the strongest confirmed ridges get the free slots
        let mut cand: [(f32, usize); crate::analysis::MAX_TRACKS] = [(0.0, 0); crate::analysis::MAX_TRACKS];
        let mut n = 0;
        for (ti, t) in tr.tracks.iter().enumerate() {
            if t.confirmed && !self.slot_track.contains(&Some(ti)) {
                cand[n] = (t.strength, ti);
                n += 1;
            }
        }
        cand[..n].sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
        let mut c = 0;
        for slot in 0..MAX_RIDGES {
            if self.slot_track[slot].is_none() && c < n {
                self.slot_track[slot] = Some(cand[c].1);
                c += 1;
            }
        }
        let hum_top = self.hum_top;
        for slot in 0..MAX_RIDGES {
            let Some(ti) = self.slot_track[slot] else { continue };
            let t = tr.tracks[ti];
            let f = (t.f + t.slope) as f64;
            // a ridge sitting on a mains harmonic is the hum notches' job
            let on_hum = f <= hum_top
                && (0..2).any(|i| {
                    let g = self.an.hum.grid_hz(i);
                    let k = (f / g).round();
                    k >= 1.0 && (f - k * g).abs() < 2.0
                });
            if on_hum || f <= 1.0 || f >= self.sr / 2.0 * 0.95 {
                self.ridges[slot].active = false;
                continue;
            }
            let sd = self.an.noise_sd_at(f, self.sr);
            self.ridges[slot].set(f, self.ridge_bw, self.sr, sd);
        }
    }

    /// One sample through the notches (the analysis sees the input before them).
    #[inline]
    pub fn run(&mut self, x: f32) -> f32 {
        if self.an.push(x) {
            self.retune();
        }
        if !self.hum[..self.n_hum].iter().any(|h| h.2.active) && !self.ridges.iter().any(|r| r.active) {
            return x;
        }
        let w = self.rng.normal() as f64;
        let mut y = x as f64;
        for h in self.hum[..self.n_hum].iter_mut().filter(|h| h.2.active) {
            y = h.2.run(y, w);
        }
        for r in self.ridges.iter_mut().filter(|r| r.active) {
            y = r.run(y, w);
        }
        y as f32
    }

    /// Ridges confirmed so far (live).
    pub fn ridges_confirmed(&self) -> usize {
        self.an.ridges.as_ref().map_or(0, |t| t.confirmed_total)
    }

    /// 50 or 60 if mains hum was seen (the stronger grid when both were), else 0.
    pub fn hum_nominal(&self) -> u32 {
        match self.hum_frames {
            [0, 0] => 0,
            [a, b] if a > b => 50,
            _ => 60,
        }
    }
}
