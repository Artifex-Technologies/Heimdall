#![no_main]
// cargo +nightly fuzz run grant_files seeds/grant_files
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::grant::fuzz_files(data));
