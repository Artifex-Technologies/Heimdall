//! The privacy pack (docs/PRIVACY_PACK.md): the downloads guard (`heimdall-fileguard`: does a downloaded file contact a server
//! when it is opened?), Remove hidden info (`heimdall-strip`: a copy without the place, the device, the author), and the
//! look-alike check of names they and the desktop share. Everything here reads hostile files: every reader has a size cap,
//! nothing recurses, and the fuzz targets (rust/fuzz, `fuzzing`) run every parser on damaged and random input.

pub mod clamav;
pub mod extract;
pub mod fuzzing;
pub mod gametime;
pub mod guard;
pub mod intake;
pub mod lookalike;
pub mod markup;
pub mod pdf;
pub mod prefs;
pub mod samples;
pub mod sandbox;
pub mod scan;
pub mod strip;
pub mod watch;
pub mod zip;
