#![no_main]
// cargo +nightly fuzz run wifi_link seeds/wifi_link -- iw's link and station text, parsed and judged (heimdalld wifi-health)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifihealth::fuzzing::link(data));
