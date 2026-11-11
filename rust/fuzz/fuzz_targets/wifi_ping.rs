#![no_main]
// cargo +nightly fuzz run wifi_ping seeds/wifi_ping -- ping's output (heimdalld wifi-health)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifihealth::fuzzing::ping(data));
