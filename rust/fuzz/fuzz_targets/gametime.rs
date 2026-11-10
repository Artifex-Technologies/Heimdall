#![no_main]
// cargo +nightly fuzz run gametime seeds/gametime
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::gametime(data));
