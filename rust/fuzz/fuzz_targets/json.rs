#![no_main]
// cargo +nightly fuzz run json seeds/json -- JSON as Go reads it (sessions, Limbo events, the config all go through it)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::json(data));
