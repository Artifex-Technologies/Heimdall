#![no_main]
// cargo +nightly fuzz run tracker seeds/tracker
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::tracker(data));
