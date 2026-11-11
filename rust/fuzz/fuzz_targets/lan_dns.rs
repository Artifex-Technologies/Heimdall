#![no_main]
// cargo +nightly fuzz run lan_dns seeds/lan_dns -- a multicast DNS answer from a device on the network, read and absorbed
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::cli::lan::fuzz::lan_dns(data));
