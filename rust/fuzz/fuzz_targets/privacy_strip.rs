#![no_main]
// cargo +nightly fuzz run privacy_strip seeds/privacy_strip -- Remove hidden info: every cleaner on hostile bytes, and its output cleaned again
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_privacy::fuzzing::strip(data));
