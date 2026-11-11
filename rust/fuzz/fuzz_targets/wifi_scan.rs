#![no_main]
// cargo +nightly fuzz run wifi_scan seeds/wifi_scan -- NetworkManager's scan list, read and weighed (heimdalld wifi-health)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifihealth::fuzzing::scan(data));
