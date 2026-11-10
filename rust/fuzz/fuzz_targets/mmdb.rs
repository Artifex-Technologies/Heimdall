#![no_main]
// cargo +nightly fuzz run mmdb seeds/mmdb -- a MaxMind DB file, opened and looked up
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::mmdb(data));
