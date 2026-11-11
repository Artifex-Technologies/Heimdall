#![no_main]
// cargo +nightly fuzz run wifi_cert seeds/wifi_cert -- certificates from the network, worded as OpenSSL words a refusal (heimdall-wifi-check)
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::wifitools::fuzzing::cert(data));
