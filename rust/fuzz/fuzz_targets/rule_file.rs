#![no_main]
// cargo +nightly fuzz run rule_file seeds/rule_file -- a text rule file: loaded or refused with messages
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::rule_file(data));
