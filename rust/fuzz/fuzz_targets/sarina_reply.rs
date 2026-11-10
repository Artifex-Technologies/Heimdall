#![no_main]
// cargo +nightly fuzz run sarina_reply seeds/sarina_reply
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::sarina_reply(data));
