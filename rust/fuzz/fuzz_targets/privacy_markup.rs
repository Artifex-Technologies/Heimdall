#![no_main]
// cargo +nightly fuzz run privacy_markup seeds/privacy_markup -- tags, attributes, entities, CSS addresses
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_privacy::fuzzing::markup(data));
