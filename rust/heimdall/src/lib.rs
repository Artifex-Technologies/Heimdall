//! Heimdall's always-on daemon in Rust: the Go daemon's detectors, engine, alerts, configuration and state files, with the
//! same findings on the same inputs (the parity fixtures and the differential run prove it, docs/RUST_PORT.md).
//!
//! The Go daemon stays installed until the switch; this one runs beside it in shadow mode first (writing its own alert log,
//! taking no responses).

pub mod alert;
pub mod api;
pub mod audit;
pub mod config;
pub mod correlate;
pub mod daemon;
pub mod detect;
pub mod engine;
pub mod event;
pub mod explain;
pub mod fuzzing;
pub mod gojson;
pub mod gonet;
pub mod gotext;
pub mod gotime;
pub mod governance;
pub mod grants;
pub mod ipintel;
pub mod maintenance;
pub mod pkgverify;
pub mod quarantine;
pub mod remoteaccess;
pub mod replay;
pub mod rules;
pub mod sources;
pub mod state;
pub mod toolrules;
pub mod verify;
