#![no_main]
// cargo +nightly fuzz run privacy_pdf seeds/privacy_pdf -- the PDF scanner: objects, object streams, dictionaries
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_privacy::fuzzing::pdf(data));
