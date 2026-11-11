#![no_main]
// cargo +nightly fuzz run wifi_json seeds/wifi_json -- JSON as Python's json reads and writes it (the Wi-Fi helpers' files, ip's answers)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifitools::fuzzing::json(data));
