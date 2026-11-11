#![no_main]
// cargo +nightly fuzz run lan_answer seeds/lan_answer -- the router's reverse-name answer and a NetBIOS node status answer
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::lan::fuzz::lan_answer(data));
