#![no_main]
// cargo +nightly fuzz run alert_line seeds/alert_line -- an alert line of either daemon's log (the shadow comparison reads both)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::alert_line(data));
