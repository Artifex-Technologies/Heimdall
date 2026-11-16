#![no_main]
// cargo +nightly fuzz run privacy_lookalike seeds/privacy_lookalike -- names: scripts, confusables, invisible and direction-changing characters
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_privacy::fuzzing::lookalike(data));
