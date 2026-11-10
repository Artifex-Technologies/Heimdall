#![no_main]
// cargo +nightly fuzz run kernel_list seeds/kernel_list
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::kernel_list(data));
