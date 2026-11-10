#![no_main]
// cargo +nightly fuzz run config seeds/config -- the daemon's config file
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::config(data));
