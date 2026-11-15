//! flyover-attack: the Doppler flyover scorer, so a defence can be measured instead of assumed.
//!
//! A propeller or engine tone glides in pitch as an aircraft passes; the curve's exact shape depends on where the listener
//! stood. Given flight tracks, this crate models that curve for every candidate place and scores how well the recording
//! matches it (the method colsto showed; a Rust rewrite of flyover-scrub's `attack.py`, `trace.py` and `physics.py`, MIT,
//! lizTheDeveloper; see rust/scrub/NOTICE). The tests in `tests/` use it to prove a scrubbed recording no longer gives its
//! place away.
//!
//! Input is plain data: audio samples, the recording's start time and [`Flight`]s of [`FlightPoint`]s (time, latitude,
//! longitude, altitude, speed, heading). There is no network code and no flight-data format in this crate.
//!
//! ```no_run
//! use flyover_attack::{rank_places, Flight, Search};
//! # let (audio, sr, start, flights): (Vec<f32>, f64, f64, Vec<Flight>) = (vec![], 16000.0, 0.0, vec![]);
//! let search = Search::around(41.9, -87.7, 0.0);
//! let r = rank_places(&audio, sr, start, &flights, &search, &Default::default());
//! if let Some(best) = r.places.first() {
//!     println!("{:.5},{:.5} score {:.3}, {:.1}x chance", best.lat, best.lon, best.score, r.strength_vs_chance);
//! }
//! ```

// the scorer walks several arrays by the same index (bins, frames, candidates)
#![allow(clippy::needless_range_loop)]

pub mod geo;
pub mod physics;
pub mod scorer;
pub mod trace;

pub use geo::{track_from_flight, Flight, FlightPoint, LocalFrame};
pub use scorer::{Box2, Scored, Spectrogram, Sweep};

/// Where to look: a square box around a point, searched on a coarse grid and refined around the best cells.
#[derive(Clone, Debug)]
pub struct Search {
    pub center_lat: f64,
    pub center_lon: f64,
    /// ground altitude of the candidate places (same datum as the flights' altitudes), metres
    pub ground_alt_m: f64,
    pub half_width_m: f64,
    pub coarse_m: f64,
    pub fine_m: f64,
    pub refine_top: usize,
}

impl Search {
    /// The reference's box: 5 km each way, a 250 m grid refined to 50 m around the twelve best cells.
    pub fn around(lat: f64, lon: f64, ground_alt_m: f64) -> Search {
        Search { center_lat: lat, center_lon: lon, ground_alt_m, half_width_m: 5000.0, coarse_m: 250.0, fine_m: 50.0, refine_top: 12 }
    }
}

/// How the recording is analysed and what is swept.
#[derive(Clone, Debug)]
pub struct Options {
    /// spectrogram window and hop, seconds; highest frequency kept, Hz
    pub window_s: f64,
    pub hop_s: f64,
    pub fmax_hz: f64,
    pub sweep: Sweep,
    /// how the flight reports are turned into a dense track
    pub track_dt_s: f64,
    pub smoothing_s: f64,
}

impl Default for Options {
    fn default() -> Options {
        Options { window_s: 1.0, hop_s: 0.25, fmax_hz: 1200.0, sweep: Sweep::default(), track_dt_s: 0.25, smoothing_s: 8.0 }
    }
}

/// One candidate place.
#[derive(Clone, Copy, Debug)]
pub struct Place {
    pub lat: f64,
    pub lon: f64,
    /// higher is a better match (mean whitened log power under the modelled curves)
    pub score: f64,
    /// the source pitch and clock offset that fitted best there
    pub f0_hz: f64,
    pub clock_offset_s: f64,
}

/// Every candidate place, best first, and how far the best stands above chance.
#[derive(Clone, Debug)]
pub struct Ranking {
    pub places: Vec<Place>,
    /// see [`scorer::strength_vs_chance`]: about 0.5 with no aircraft, 4 or more reads as a real line
    pub strength_vs_chance: f64,
}

/// Score candidate places for one recording (mono samples at `sr`, starting at `recording_start_s` on the flights' clock)
/// against the given flights, best first. Flights with fewer than four usable reports are skipped.
pub fn rank_places(audio: &[f32], sr: f64, recording_start_s: f64, flights: &[Flight], search: &Search, opts: &Options) -> Ranking {
    let frame = LocalFrame::new(search.center_lat, search.center_lon, search.ground_alt_m);
    let tracks: Vec<physics::Track> =
        flights.iter().filter_map(|f| track_from_flight(f, &frame, opts.track_dt_s, opts.smoothing_s)).collect();
    let spec = scorer::whitened_spectrogram(audio, sr, opts.window_s, opts.hop_s, opts.fmax_hz);
    let area = Box2 {
        center: (0.0, 0.0),
        half_width: search.half_width_m,
        coarse: search.coarse_m,
        fine: search.fine_m,
        refine_top: search.refine_top,
    };
    let found = scorer::locate(&spec, &tracks, recording_start_s, &area, &opts.sweep);
    let null = scorer::locate(&spec.reversed(), &tracks, recording_start_s, &area, &opts.sweep);
    let places = found
        .ranked()
        .into_iter()
        .filter(|&i| found.scores[i].is_finite())
        .map(|i| {
            let c = found.candidates[i];
            let (lat, lon) = frame.to_latlon(c[0], c[1]);
            Place { lat, lon, score: found.scores[i], f0_hz: found.best_f0[i], clock_offset_s: found.best_offset[i] }
        })
        .collect();
    Ranking { places, strength_vs_chance: scorer::strength_vs_chance(&found, &null) }
}
