#![no_main]
// cargo +nightly fuzz run wifi_tools seeds/wifi_tools -- ss, heimdalld origin and addresses as the Wi-Fi check reads them
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifitools::fuzzing::tools(data));
