#![no_main]
// cargo +nightly fuzz run macvendor seeds/macvendor -- the IEEE registry files (text lists and CSV), names, addresses
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_macvendor::fuzzing::parsers(data));
