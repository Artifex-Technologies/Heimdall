#![no_main]
// cargo +nightly fuzz run wifi_http seeds/wifi_http -- a web server's answer as urllib reads it, and its redirect (heimdall-wifi-check)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifitools::fuzzing::http(data));
