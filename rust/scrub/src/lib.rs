//! heimdall-scrub: removes what can place or date a recording from its sound.
//!
//! Two leaks live in the low end of every microphone recording:
//! - **Aircraft overhead.** A propeller or engine tone, even one nobody can hear, glides in pitch as the aircraft passes
//!   (Doppler). The curve's exact shape depends on where the listener stood; matched against public flight tracks
//!   (ADS-B), it places a recording to within a few hundred metres (shown by colsto; flyover-scrub is the defence this
//!   crate is a Rust rewrite of, MIT, see NOTICE).
//! - **Mains hum (ENF).** The grid's 50 or 60 Hz wanders by hundredths of a hertz, the same at every socket of one
//!   grid; hum picked up by a microphone records that wander, so it can date a recording and say which grid it was made on.
//!
//! Two modes:
//! - [`offline`]: files, with lookahead (the reference algorithm). [`offline::scrub`] for a buffer, [`offline::Offline`]
//!   to stream an hour of audio in megabytes.
//! - [`live`]: the private microphone, causal, about 21 ms of added latency at 48 kHz, no allocation while running.
//!
//! And, off by default, [`disguise`]: a pitch and formant shift with a little slow jitter that hides casual recognition of
//! the voice (after the scrub, live and for files).
//!
//! Both keep the foreground (speech) and everything above 2 kHz, and re-synthesise or remove the rest of the band. It is
//! evidence, not a guarantee: see docs/LOCATION_SOUNDS.md in the Heimdall repository for what it cannot protect.

// DSP loops walk several arrays by the same index (bins, frames, taps); written as index loops they read like the maths
#![allow(clippy::needless_range_loop)]

pub mod analysis;
pub mod complex;
pub mod config;
pub mod detect;
pub mod disguise;
pub mod fft;
pub mod filters;
pub mod live;
pub mod nd;
pub mod offline;
pub mod rng;
pub mod stage;

pub use config::{Config, Report};
