//! Video and the sound formats our own code does not rewrite (MP4/MOV/M4A/3GP, Matroska/WebM, Ogg/Opus, AVI, ASF): ffmpeg
//! copies the picture, sound and subtitle streams as they are (no re-encoding) and leaves out every tag (the place a phone
//! wrote, ©xyz and com.apple.quicktime.location.ISO6709 included), chapters, and data tracks (a camera's GPS track). Only
//! the audio and subtitle languages are written again. ffprobe says first what was there. Both run as argv (never a shell),
//! with `file:` before every path so no name is read as an option or another protocol.

use super::{note, Removed};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The ffmpeg format to write, from the file's first bytes; None: not a kind handled here.
pub fn muxer(head: &[u8]) -> Option<&'static str> {
    let at = |i: usize, m: &[u8]| head.len() >= i + m.len() && &head[i..i + m.len()] == m;
    if at(4, b"ftyp") {
        let brand = head.get(8..12).unwrap_or(b"");
        return Some(match brand {
            b"qt  " => "mov",
            b"3gp4" | b"3gp5" | b"3gp6" | b"3gp7" | b"3gs7" => "3gp",
            b"3g2a" | b"3g2b" | b"3g2c" => "3g2",
            b"heic" | b"heix" | b"mif1" | b"msf1" | b"avif" | b"avis" | b"heim" | b"heis" | b"hevc" => return None,
            _ => "mp4",
        });
    }
    if at(4, b"moov") || at(4, b"mdat") || at(4, b"wide") {
        return Some("mov");
    }
    if at(0, b"\x1A\x45\xDF\xA3") {
        let doc_webm = head.windows(4).take(64).any(|w| w == b"webm");
        return Some(if doc_webm { "webm" } else { "matroska" });
    }
    if at(0, b"OggS") {
        return Some("ogg");
    }
    if at(0, b"RIFF") && at(8, b"AVI ") {
        return Some("avi");
    }
    if at(0, b"\x30\x26\xB2\x75\x8E\x66\xCF\x11") {
        return Some("asf");
    }
    None
}

fn input(p: &Path) -> std::ffi::OsString {
    let abs = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(p) };
    let mut s = std::ffi::OsString::from("file:");
    s.push(abs.as_os_str());
    s
}

/// Runs a program with a time limit; its standard output (8 MiB at most) and whether it succeeded.
fn run(cmd: &mut Command, limit: Duration) -> Result<(bool, Vec<u8>, String), String> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("could not start {}: {e}", cmd.get_program().to_string_lossy()))?;
    let out = child.stdout.take();
    let err = child.stderr.take();
    let o = std::thread::spawn(move || {
        let mut b = vec![];
        if let Some(o) = out {
            let _ = std::io::Read::read_to_end(&mut std::io::Read::take(o, 8 << 20), &mut b);
        }
        b
    });
    let e = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(e) = err {
            let _ = std::io::Read::read_to_string(&mut std::io::Read::take(e, 64 << 10), &mut s);
        }
        s
    });
    let start = Instant::now();
    let ok = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s.success(),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("it took too long".into());
            }
        }
    };
    Ok((ok, o.join().unwrap_or_default(), e.join().unwrap_or_default()))
}

/// Tag names in plain words.
fn tag_words(k: &str) -> &'static str {
    let k = k.to_ascii_lowercase();
    if k.contains("location") || k.contains("xyz") || k.contains("gps") {
        "Location"
    } else if k.contains("creation_time") || k == "date" || k.contains("date") {
        "Recording date"
    } else if k.contains("make") || k.contains("model") || k.contains("device") {
        "Device make and model"
    } else if k.contains("software") || k == "encoder" || k.contains("encoded_by") || k.contains("tool") {
        "Software"
    } else if [
        "title",
        "artist",
        "album",
        "album_artist",
        "comment",
        "description",
        "copyright",
        "author",
        "composer",
        "genre",
        "lyrics",
        "synopsis",
    ]
    .iter()
    .any(|t| k == *t)
    {
        "Title, artist and comments"
    } else {
        "Other tags"
    }
}

/// The languages to write again: (stream type letter, index within the type, language).
type Langs = Vec<(char, usize, String)>;

/// What ffprobe sees: the tags in plain words, and the languages of the streams kept.
pub fn describe(p: &Path, r: &mut Removed) -> Result<Langs, String> {
    let (ok, out, _) = run(
        Command::new("ffprobe").args(["-v", "error", "-show_format", "-show_streams", "-show_chapters", "-of", "json", "-i"]).arg(input(p)),
        Duration::from_secs(60),
    )?;
    if !ok {
        return Err("ffprobe could not read it".into());
    }
    let v: serde_json::Value = serde_json::from_slice(&out).map_err(|_| "ffprobe's answer could not be read")?;
    let skip = ["major_brand", "minor_version", "compatible_brands", "language", "handler_name", "vendor_id", "duration", "encoder"];
    let words = |tags: &serde_json::Value, r: &mut Removed| {
        if let Some(m) = tags.as_object() {
            for k in m.keys() {
                let lk = k.to_ascii_lowercase();
                if !skip.contains(&lk.as_str())
                    || lk == "encoder" && tags.get(k).and_then(|x| x.as_str()).is_some_and(|s| !s.starts_with("Lavf"))
                {
                    note(r, tag_words(k));
                }
            }
        }
    };
    words(&v["format"]["tags"], r);
    let mut langs = vec![];
    let mut counts = [0usize; 3];
    for s in v["streams"].as_array().cloned().unwrap_or_default() {
        let ty = s["codec_type"].as_str().unwrap_or("");
        let slot = match ty {
            "video" => Some((0, 'v')),
            "audio" => Some((1, 'a')),
            "subtitle" => Some((2, 's')),
            "data" | "attachment" => {
                note(r, "Data tracks (a camera's GPS track, timed location, other data)");
                None
            }
            _ => None,
        };
        words(&s["tags"], r);
        if let Some((i, letter)) = slot {
            if let Some(l) = s["tags"]["language"]
                .as_str()
                .filter(|l| (2..=3).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_lowercase()) && *l != "und")
            {
                langs.push((letter, counts[i], l.to_string()));
            }
            counts[i] += 1;
        }
    }
    if v["chapters"].as_array().is_some_and(|c| !c.is_empty()) {
        note(r, "Chapters");
    }
    Ok(langs)
}

/// Writes the cleaned copy to `out` (which must not exist; ffmpeg is told never to overwrite).
pub fn strip(input_path: &Path, out: &Path, fmt: &str, r: &mut Removed) -> Result<(), String> {
    let langs = describe(input_path, r)?;
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-nostdin", "-hide_banner", "-loglevel", "error", "-n", "-i"]).arg(input(input_path));
    cmd.args(["-map", "0:v?", "-map", "0:a?", "-map", "0:s?", "-c", "copy", "-map_metadata", "-1"]);
    cmd.args(["-map_metadata:s:v", "-1", "-map_metadata:s:a", "-1", "-map_metadata:s:s", "-1", "-map_chapters", "-1"]);
    cmd.args(["-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact"]);
    for (t, i, l) in &langs {
        cmd.arg(format!("-metadata:s:{t}:{i}")).arg(format!("language={l}"));
    }
    cmd.args(["-f", fmt]).arg(self::input(out));
    let (ok, _, err) = run(&mut cmd, Duration::from_secs(3600))?;
    if !ok {
        let last = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("ffmpeg failed").trim().to_string();
        return Err(format!("ffmpeg: {last}"));
    }
    Ok(())
}

/// ffmpeg and ffprobe are both on PATH.
pub fn available() -> bool {
    ["ffmpeg", "ffprobe"]
        .iter()
        .all(|p| std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join(p).is_file())))
}
