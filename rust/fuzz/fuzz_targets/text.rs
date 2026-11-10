#![no_main]
// cargo +nightly fuzz run text seeds/text -- bytes from outside: Go's reading of them, redaction, escapes, RFC 3339 times
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::text(data));
