//! The knobs, with the reference's defaults (flyover-scrub's ScrubConfig) and what each one is for.

/// Settings for both modes. `Config::default()` is what the file tool and the live microphone use.
#[derive(Clone, Debug)]
pub struct Config {
    /// The protected band in Hz: aircraft tones, engine harmonics and mains hum live here. Above it nothing changes.
    pub band: (f32, f32),
    /// Analysis window in seconds (rounded to a power-of-two length): about 4 Hz bins, long enough to tell a slow tone
    /// from speech.
    pub window_s: f32,
    /// Width of the median across frequency that estimates the noise floor (a narrow line cannot move it).
    pub floor_freq_hz: f32,
    /// Smoothing of the floor over time.
    pub floor_time_s: f32,
    /// Bins this far above the floor are foreground (speech, music) and kept; quieter ones are re-synthesised.
    pub foreground_db: f32,
    /// A ridge starts at this height above the floor. Low on purpose: a false ridge in noise costs nothing.
    pub ridge_db: f32,
    /// A ridge this long is a signature (an aircraft, a drone, traffic, a fan).
    pub ridge_min_s: f32,
    /// Aircraft glide slowly; speech pitch moves fast. Ridges steeper than this are not followed.
    pub ridge_max_slope_hz_s: f32,
    /// Removed on each side of a ridge.
    pub ridge_pad_hz: f32,
    /// Keep steady tones (mains hum, fridge): the mains hum dates a recording (ENF), so the default removes it.
    pub keep_hum: bool,
    /// How far a tone may wander and still count as steady (for `keep_hum`).
    pub stationary_max_drift_hz: f32,
    /// The mains-hum harmonics (of 50 and 60 Hz) removed by the tracking notches, up to this frequency.
    pub hum_max_hz: f32,
    /// Fixed noise seed (tests); `None` takes one from the operating system.
    pub seed: Option<u64>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            band: (20.0, 2000.0),
            window_s: 0.25,
            floor_freq_hz: 120.0,
            floor_time_s: 3.0,
            foreground_db: 12.0,
            ridge_db: 4.0,
            ridge_min_s: 1.5,
            ridge_max_slope_hz_s: 40.0,
            ridge_pad_hz: 8.0,
            keep_hum: false,
            stationary_max_drift_hz: 1.5,
            hum_max_hz: 1000.0,
            seed: None,
        }
    }
}

/// What a scrub did, for the file tool's summary and the tests.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// In-band bins (time x frequency) replaced by noise: background and ridges.
    pub replaced_fraction: f64,
    /// In-band bins removed as parts of ridges.
    pub ridge_fraction: f64,
    /// Ridges found.
    pub ridges_found: usize,
    /// Mains hum seen while scrubbing: 50 or 60 (Hz), or 0.
    pub hum_nominal_hz: u32,
}
