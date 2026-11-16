#![no_main]
// cargo +nightly fuzz run privacy_guard seeds/privacy_guard -- the downloads guard: is a hostile file read safely under every name (Office, PDF, SVG, playlists, shortcuts, ZIP)?
libfuzzer_sys::fuzz_target!(|data: &[u8]| heimdall_privacy::fuzzing::guard(data));
