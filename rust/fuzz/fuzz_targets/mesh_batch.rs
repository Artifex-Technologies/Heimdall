#![no_main]
// cargo +nightly fuzz run mesh_batch seeds/mesh_batch
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall::fuzzing::mesh_batch(data));
