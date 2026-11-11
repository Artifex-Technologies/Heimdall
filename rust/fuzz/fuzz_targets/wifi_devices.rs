#![no_main]
// cargo +nightly fuzz run wifi_devices seeds/wifi_devices -- the API's device list, as wifi-health counts it
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifihealth::fuzzing::devices(data));
