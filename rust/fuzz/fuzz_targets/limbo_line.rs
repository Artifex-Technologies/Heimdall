#![no_main]
// cargo +nightly fuzz run limbo_line seeds/limbo_line -- one line of Limbo's events.jsonl
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::limbo_line(data));
