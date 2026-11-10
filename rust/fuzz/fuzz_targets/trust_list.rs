#![no_main]
// cargo +nightly fuzz run trust_list seeds/trust_list
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::trust_list(data));
