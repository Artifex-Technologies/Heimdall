#![no_main]
// cargo +nightly fuzz run privacy_zip seeds/privacy_zip -- the ZIP reader: directories, ZIP64, inflating with caps
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_privacy::fuzzing::zip(data));
