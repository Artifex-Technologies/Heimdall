#![no_main]
// cargo +nightly fuzz run http_request seeds/http_request
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::http_request(data));
