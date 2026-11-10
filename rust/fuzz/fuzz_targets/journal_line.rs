#![no_main]
// cargo +nightly fuzz run journal_line seeds/journal_line -- one journalctl -o json line, and a threat list
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::journal_line(data));
