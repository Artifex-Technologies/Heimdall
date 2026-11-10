#![no_main]
// cargo +nightly fuzz run event_line seeds/event_line -- an event through every detector, verified, written as an alert
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::event_line(data));
