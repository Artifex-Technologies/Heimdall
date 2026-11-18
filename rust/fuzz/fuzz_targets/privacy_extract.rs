#![no_main]
// cargo +nightly fuzz run privacy_extract seeds/privacy_extract -- safe extraction's dry run: ZIP, tar, gzip, names, limits
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_privacy::fuzzing::extract(data));
