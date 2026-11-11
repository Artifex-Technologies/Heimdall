#![no_main]
// cargo +nightly fuzz run wifi_wireguard seeds/wifi_wireguard -- a WireGuard file and the lockdown rules made from it (heimdall-wifi-guard)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifitools::fuzzing::wireguard(data));
