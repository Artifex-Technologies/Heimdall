//! heimdall-scrub as Minos and Settings run it: the output lines, the exit codes, and never writing over a file.
//! Needs ffmpeg and ffprobe for the scrubbing itself; without them those parts are skipped (the refusals still run).

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_heimdall-scrub"))
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("heimdall-scrub-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A 16-bit mono WAV of `seconds` of quiet noise with a 120 Hz hum, written by hand (no ffmpeg needed).
fn wav(path: &Path, seconds: u32) {
    let sr = 16000u32;
    let n = sr * seconds;
    let mut data = Vec::with_capacity(n as usize * 2);
    let mut x = 12345u32;
    for i in 0..n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let noise = ((x >> 16) as f32 / 32768.0 - 1.0) * 0.02;
        let hum = 0.05 * (2.0 * std::f32::consts::PI * 120.0 * i as f32 / sr as f32).sin();
        data.extend_from_slice(&(((noise + hum) * 32767.0) as i16).to_le_bytes());
    }
    let mut f = Vec::new();
    f.extend_from_slice(b"RIFF");
    f.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
    f.extend_from_slice(b"WAVEfmt ");
    f.extend_from_slice(&16u32.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&sr.to_le_bytes());
    f.extend_from_slice(&(sr * 2).to_le_bytes());
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&16u16.to_le_bytes());
    f.extend_from_slice(b"data");
    f.extend_from_slice(&(data.len() as u32).to_le_bytes());
    f.extend_from_slice(&data);
    std::fs::write(path, f).unwrap();
}

fn have_ffmpeg() -> bool {
    ["ffmpeg", "ffprobe"].iter().all(|p| Command::new(p).arg("-version").output().is_ok_and(|o| o.status.success()))
}

#[test]
fn usage_and_refusals() {
    let d = dir("refuse");
    let a = d.join("a.wav");
    wav(&a, 2);
    let st = Command::new(bin()).arg(&a).output().unwrap();
    assert_eq!(st.status.code(), Some(2));
    let st = Command::new(bin()).arg(&a).arg(&a).output().unwrap();
    assert_eq!(st.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&st.stderr).starts_with("heimdall-scrub: "));
    let b = d.join("b.wav");
    std::fs::write(&b, b"keep me").unwrap();
    let st = Command::new(bin()).arg(&a).arg(&b).output().unwrap();
    assert_eq!(st.status.code(), Some(1));
    assert_eq!(std::fs::read(&b).unwrap(), b"keep me");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn scrubs_a_copy_and_says_where() {
    if !have_ffmpeg() {
        eprintln!("ffmpeg/ffprobe not found: skipped");
        return;
    }
    let d = dir("scrub");
    let a = d.join("-a b.wav");
    wav(&a, 4);
    let out = d.join("-a b (scrubbed).wav");
    let r = Command::new(bin()).arg("--progress").arg("--seed").arg("1").arg("--").arg(&a).arg(&out).output().unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    let text = String::from_utf8_lossy(&r.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.iter().any(|l| l.starts_with("progress ")));
    assert_eq!(lines.last().copied(), Some(format!("wrote {}", out.display()).as_str()));
    assert!(std::fs::metadata(&out).unwrap().len() > 100_000);
    // no temporary folder left behind
    let left: Vec<_> = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".heimdall-scrub-"))
        .collect();
    assert!(left.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}
