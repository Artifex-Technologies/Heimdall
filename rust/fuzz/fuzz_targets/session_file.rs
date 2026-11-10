#![no_main]
// cargo +nightly fuzz run session_file seeds/session_file -- a Sarina session file as the session watcher reads it
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::session_file(data));
