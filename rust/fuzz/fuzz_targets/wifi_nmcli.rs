#![no_main]
// cargo +nightly fuzz run wifi_nmcli seeds/wifi_nmcli -- NetworkManager's terse lines, split and read (heimdall-wifi-check, heimdall-wifi-guard)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifitools::fuzzing::nmcli(data));
