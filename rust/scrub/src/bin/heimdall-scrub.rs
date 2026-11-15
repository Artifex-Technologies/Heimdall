//! heimdall-scrub: a scrubbed copy of an audio or video file, without the sounds that can place or date it (aircraft
//! overhead, mains hum) and without its metadata (GPS, dates, device). The video stream is copied untouched.
//!
//!     heimdall-scrub IN OUT                 write a scrubbed copy (never over IN; OUT must not exist without --force)
//!     heimdall-scrub --check IN             report long gliding tones and mains hum, write nothing
//!
//! ffmpeg and ffprobe do the decoding and encoding, started with their arguments one by one (never through a shell), and
//! every file name goes to them as `file:/absolute/path`, so a name like `-x.mp4` or `concat:a|b` is only ever a file.

#![allow(clippy::needless_range_loop)]

use std::ffi::OsString;
use std::io::{BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use heimdall_scrub::detect::{detect_enf, detect_ridges};
use heimdall_scrub::live::Live;
use heimdall_scrub::offline::Offline;
use heimdall_scrub::{Config, Report};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

const USAGE: &str = "usage: heimdall-scrub [--keep-hum] [--keep-metadata] [--live] [--progress] [--force] [--seed N] IN OUT
       heimdall-scrub --check IN

Writes a copy of IN to OUT without the sounds that can place or date a recording: aircraft tones (the Doppler curve of a
plane overhead can be matched to flight tracks) and mains hum (its wander dates a recording and names the power grid).
Speech and everything above 2 kHz are kept. Video is copied untouched; metadata (GPS, dates, device) is removed.

  --keep-hum       keep steady tones such as mains hum (not recommended)
  --keep-metadata  keep the container's tags and chapters
  --live           use the live (causal) scrub instead of the whole-file one
  --progress       print 'progress 0.42' lines while working
  --force          replace OUT if it exists (never IN)
  --seed N         fixed noise seed (for tests)
  --check          report tones and hum in IN and write nothing";

struct Args {
    input: PathBuf,
    output: Option<PathBuf>,
    check: bool,
    keep_hum: bool,
    keep_metadata: bool,
    live: bool,
    progress: bool,
    force: bool,
    seed: Option<u64>,
}

fn parse(argv: Vec<OsString>) -> Result<Args, String> {
    let mut a = Args {
        input: PathBuf::new(),
        output: None,
        check: false,
        keep_hum: false,
        keep_metadata: false,
        live: false,
        progress: false,
        force: false,
        seed: None,
    };
    let mut files = Vec::new();
    let mut it = argv.into_iter();
    let mut only_files = false;
    while let Some(s) = it.next() {
        let b = s.as_bytes();
        if only_files || !b.starts_with(b"-") || b == b"-" {
            files.push(PathBuf::from(s));
            continue;
        }
        match b {
            b"--" => only_files = true,
            b"--check" => a.check = true,
            b"--keep-hum" => a.keep_hum = true,
            b"--keep-metadata" => a.keep_metadata = true,
            b"--live" => a.live = true,
            b"--progress" => a.progress = true,
            b"--force" => a.force = true,
            b"--seed" => {
                let v = it.next().ok_or("--seed needs a number")?;
                a.seed = Some(v.to_str().and_then(|v| v.parse().ok()).ok_or("--seed needs a number")?);
            }
            _ => return Err(format!("unknown option {}", s.to_string_lossy())),
        }
    }
    match (a.check, files.len()) {
        (true, 1) => a.input = files.remove(0),
        (false, 2) => {
            a.output = Some(files.remove(1));
            a.input = files.remove(0);
        }
        _ => return Err("expected IN OUT (or --check IN)".into()),
    }
    Ok(a)
}

/// `file:/absolute/path` for ffmpeg: never an option, never another protocol.
fn ff_path(p: &Path) -> OsString {
    let mut s = OsString::from("file:");
    s.push(p.as_os_str());
    s
}

fn absolute(p: &Path) -> Result<PathBuf, String> {
    std::path::absolute(p).map_err(|e| format!("{}: {e}", p.display()))
}

#[derive(Debug, Clone)]
struct AudioStream {
    sample_rate: u32,
    channels: u32,
}

struct Probe {
    audio: Vec<AudioStream>,
    has_video: bool,
    duration: f64,
}

fn probe(input: &Path) -> Result<Probe, String> {
    let out = Command::new("ffprobe")
        .args(["-v", "error", "-show_entries", "stream=index,codec_type,sample_rate,channels:stream_disposition=attached_pic"])
        .args(["-show_entries", "format=duration", "-of", "compact=p=0"])
        .arg(ff_path(input))
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("ffprobe could not be started ({e}); install ffmpeg"))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        return Err(format!("ffprobe could not read the file: {}", msg.lines().last().unwrap_or("unknown error")));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut p = Probe { audio: Vec::new(), has_video: false, duration: 0.0 };
    for line in text.lines() {
        let kv: Vec<(&str, &str)> = line.split('|').filter_map(|f| f.split_once('=')).collect();
        let get = |k: &str| kv.iter().find(|(a, _)| *a == k).map(|(_, v)| *v);
        if let Some(d) = get("duration") {
            if get("codec_type").is_none() {
                p.duration = d.parse().unwrap_or(0.0);
                continue;
            }
        }
        match get("codec_type") {
            Some("audio") => p.audio.push(AudioStream {
                sample_rate: get("sample_rate").and_then(|v| v.parse().ok()).unwrap_or(0),
                channels: get("channels").and_then(|v| v.parse().ok()).unwrap_or(0),
            }),
            Some("video") if get("disposition:attached_pic") != Some("1") => p.has_video = true,
            _ => {}
        }
    }
    Ok(p)
}

/// The audio encoder for the output's container, by extension.
fn audio_codec(out: &Path) -> Vec<&'static str> {
    let ext = out.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "mp4" | "m4v" | "mov" | "m4a" | "3gp" | "3g2" | "aac" => vec!["-c:a", "aac", "-b:a", "256k"],
        "mkv" | "mka" | "flac" => vec!["-c:a", "flac"],
        "webm" | "opus" | "ogg" | "oga" => vec!["-c:a", "libopus", "-b:a", "192k"],
        "mp3" => vec!["-c:a", "libmp3lame", "-b:a", "256k"],
        "wav" => vec!["-c:a", "pcm_f32le"],
        "aif" | "aiff" => vec!["-c:a", "pcm_s24be"],
        _ => vec![],
    }
}

fn audio_only_container(out: &Path) -> bool {
    let ext = out.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    matches!(ext.as_str(), "wav" | "flac" | "mp3" | "ogg" | "oga" | "opus" | "m4a" | "mka" | "aac" | "aif" | "aiff")
}

/// A private folder next to the output (same file system, so the result can be linked into place), removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(near: &Path) -> Result<TempDir, String> {
        let parent = near.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let r = heimdall_scrub::rng::Rng::from_os().next_u64();
        let dir = parent.join(format!(".heimdall-scrub-{}-{:016x}", std::process::id(), r));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(TempDir(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A child that is killed and reaped if dropped early (a stop, an error).
struct Guard(Option<Child>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(c) = self.0.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Guard {
    fn finish(mut self, what: &str) -> Result<(), String> {
        let mut c = self.0.take().unwrap();
        let mut err = String::new();
        if let Some(mut e) = c.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        let st = c.wait().map_err(|e| format!("{what}: {e}"))?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("{what} failed: {}", err.lines().last().unwrap_or("no message")))
        }
    }
}

enum Scrubber {
    Whole(Box<Offline>),
    Live(Box<Live>, usize),
}

impl Scrubber {
    fn new(cfg: &Config, sr: f64, live: bool) -> Scrubber {
        if live {
            let l = Live::new(cfg, sr);
            let lat = l.latency();
            Scrubber::Live(Box::new(l), lat)
        } else {
            Scrubber::Whole(Box::new(Offline::new(cfg, sr)))
        }
    }

    fn push(&mut self, x: &[f32], out: &mut Vec<f32>) {
        match self {
            Scrubber::Whole(o) => {
                o.push(x);
                o.pull(out);
            }
            Scrubber::Live(l, skip) => {
                let mut y = vec![0.0; x.len()];
                l.process(x, &mut y);
                let s = (*skip).min(y.len());
                *skip -= s;
                out.extend_from_slice(&y[s..]);
            }
        }
    }

    fn finish(&mut self, out: &mut Vec<f32>) {
        match self {
            Scrubber::Whole(o) => {
                o.finish();
                o.pull(out);
            }
            Scrubber::Live(l, _) => {
                let n = l.latency();
                let mut y = vec![0.0; n];
                l.process(&vec![0.0; n], &mut y);
                out.extend_from_slice(&y);
            }
        }
    }

    fn report(&self) -> Report {
        match self {
            Scrubber::Whole(o) => o.report(),
            Scrubber::Live(l, _) => l.report(),
        }
    }
}

struct Progress {
    on: bool,
    last: f64,
}

impl Progress {
    fn set(&mut self, v: f64) {
        let v = v.clamp(0.0, 1.0);
        if self.on && (v - self.last >= 0.005 || (v >= 1.0 && self.last < 1.0)) {
            self.last = v;
            println!("progress {v:.3}");
            let _ = std::io::stdout().flush();
        }
    }
}

fn stopped() -> Result<(), String> {
    if STOP.load(Ordering::SeqCst) {
        Err("stopped".into())
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
/// Decode one audio stream, scrub every channel, write raw interleaved f32 to `raw`. Returns the report of channel 0 and
/// the peak.
fn scrub_stream(
    input: &Path,
    idx: usize,
    st: &AudioStream,
    raw: &Path,
    cfg: &Config,
    live: bool,
    total: f64,
    prog: &mut Progress,
    base: f64,
    share: f64,
) -> Result<(Report, f32), String> {
    let ch = st.channels.max(1) as usize;
    let sr = st.sample_rate.max(1);
    let child = Command::new("ffmpeg")
        .args(["-nostdin", "-hide_banner", "-v", "error", "-i"])
        .arg(ff_path(input))
        .args(["-map", &format!("0:a:{idx}"), "-vn", "-sn", "-dn", "-f", "f32le", "-acodec", "pcm_f32le"])
        .args(["-ac", &ch.to_string(), "-ar", &sr.to_string(), "pipe:1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("ffmpeg could not be started ({e}); install ffmpeg"))?;
    let mut guard = Guard(Some(child));
    let mut stdout = guard.0.as_mut().unwrap().stdout.take().unwrap();
    let mut w = BufWriter::new(std::fs::File::create(raw).map_err(|e| format!("{}: {e}", raw.display()))?);
    let mut sc: Vec<Scrubber> = (0..ch).map(|_| Scrubber::new(cfg, sr as f64, live)).collect();
    let mut outs: Vec<Vec<f32>> = vec![Vec::new(); ch];
    let mut buf = vec![0u8; 1 << 18];
    let mut pending: Vec<u8> = Vec::new();
    let mut chans: Vec<Vec<f32>> = vec![Vec::new(); ch];
    let mut frames_in = 0u64;
    let mut peak = 0.0f32;
    let write_ready = |outs: &mut Vec<Vec<f32>>, w: &mut BufWriter<std::fs::File>, peak: &mut f32| -> Result<(), String> {
        let n = outs.iter().map(|o| o.len()).min().unwrap_or(0);
        let mut bytes = Vec::with_capacity(n * ch * 4);
        for i in 0..n {
            for o in outs.iter() {
                *peak = peak.max(o[i].abs());
                bytes.extend_from_slice(&o[i].to_le_bytes());
            }
        }
        for o in outs.iter_mut() {
            o.drain(..n);
        }
        w.write_all(&bytes).map_err(|e| format!("writing the temporary audio: {e}"))
    };
    loop {
        stopped()?;
        let got = stdout.read(&mut buf).map_err(|e| format!("reading from ffmpeg: {e}"))?;
        if got == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..got]);
        let frame_bytes = 4 * ch;
        let whole = pending.len() / frame_bytes * frame_bytes;
        for c in chans.iter_mut() {
            c.clear();
        }
        for f in pending[..whole].chunks_exact(frame_bytes) {
            for (c, s) in f.chunks_exact(4).enumerate() {
                chans[c].push(f32::from_le_bytes([s[0], s[1], s[2], s[3]]));
            }
        }
        pending.drain(..whole);
        frames_in += (whole / frame_bytes) as u64;
        for c in 0..ch {
            sc[c].push(&chans[c], &mut outs[c]);
        }
        write_ready(&mut outs, &mut w, &mut peak)?;
        if total > 0.0 {
            prog.set(base + share * (frames_in as f64 / sr as f64 / total).min(1.0));
        }
    }
    drop(stdout);
    guard.finish("decoding")?;
    for c in 0..ch {
        sc[c].finish(&mut outs[c]);
    }
    write_ready(&mut outs, &mut w, &mut peak)?;
    w.flush().map_err(|e| format!("writing the temporary audio: {e}"))?;
    Ok((sc[0].report(), peak))
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

fn scrub_file(a: &Args) -> Result<(), String> {
    let input = absolute(&a.input)?;
    let output = absolute(a.output.as_ref().unwrap())?;
    let meta = std::fs::metadata(&input).map_err(|e| format!("{}: {e}", input.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", input.display()));
    }
    if input == output || same_file(&input, &output) {
        return Err("OUT is the input file; the original is never replaced".into());
    }
    if output.symlink_metadata().is_ok() && !a.force {
        return Err(format!("{} exists (use --force to replace it)", output.display()));
    }
    let p = probe(&input)?;
    if p.audio.is_empty() {
        return Err("the file has no sound".into());
    }
    let cfg = Config { keep_hum: a.keep_hum, seed: a.seed, ..Config::default() };
    let tmp = TempDir::new(&output)?;
    let mut prog = Progress { on: a.progress, last: -1.0 };
    prog.set(0.0);
    let n = p.audio.len();
    let mut raws = Vec::new();
    let mut summary = Vec::new();
    for (i, st) in p.audio.iter().enumerate() {
        if st.sample_rate == 0 || st.channels == 0 {
            return Err(format!("audio stream {i} has no sample rate or channel count"));
        }
        let raw = tmp.0.join(format!("a{i}.f32"));
        let (rep, peak) =
            scrub_stream(&input, i, st, &raw, &cfg, a.live, p.duration, &mut prog, 0.95 * i as f64 / n as f64, 0.95 / n as f64)?;
        summary.push(format!(
            "audio {i}: {} Hz, {} ch | tonal ridges: {} | in-band bins replaced: {:.0}% | mains hum: {}{}",
            st.sample_rate,
            st.channels,
            rep.ridges_found,
            100.0 * rep.replaced_fraction,
            if rep.hum_nominal_hz > 0 { format!("{} Hz, removed", rep.hum_nominal_hz) } else { "none heard".into() },
            if peak > 1.0 {
                format!(" | peak {:+.1} dBFS (formats without float samples clip it)", 20.0 * peak.log10())
            } else {
                String::new()
            }
        ));
        raws.push((raw, st.clone()));
    }
    stopped()?;
    let ext = output.extension().map(|e| e.to_os_string()).unwrap_or_default();
    let mut tmp_out = tmp.0.join("out");
    if !ext.is_empty() {
        tmp_out.set_extension(&ext);
    }
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-nostdin", "-hide_banner", "-v", "error", "-i"]).arg(ff_path(&input));
    for (raw, st) in &raws {
        cmd.args(["-f", "f32le", "-ar", &st.sample_rate.to_string(), "-ac", &st.channels.to_string(), "-i"]).arg(ff_path(raw));
    }
    let video = p.has_video && !audio_only_container(&output);
    if video {
        // V: video streams that are not cover art (a picture can carry its own EXIF location)
        cmd.args(["-map", "0:V", "-c:v", "copy"]);
    }
    for i in 0..raws.len() {
        cmd.args(["-map", &format!("{}:a", i + 1)]);
    }
    cmd.args(audio_codec(&output));
    if !a.keep_metadata {
        cmd.args(["-map_metadata", "-1", "-map_chapters", "-1", "-fflags", "+bitexact", "-flags:a", "+bitexact"]);
        if video {
            cmd.args(["-map_metadata:s:v", "-1"]);
        }
    } else {
        cmd.args(["-map_metadata", "0"]);
    }
    cmd.arg(ff_path(&tmp_out));
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| format!("ffmpeg: {e}"))?;
    let mut g = Guard(Some(child));
    // the mux is quick; poll so a stop still ends it
    loop {
        if STOP.load(Ordering::SeqCst) {
            return Err("stopped".into());
        }
        match g.0.as_mut().unwrap().try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(e) => return Err(format!("ffmpeg: {e}")),
        }
    }
    g.finish("encoding")?;
    // never over an existing file unless asked: a hard link fails if OUT appeared meanwhile
    if a.force {
        std::fs::rename(&tmp_out, &output).map_err(|e| format!("{}: {e}", output.display()))?;
    } else {
        std::fs::hard_link(&tmp_out, &output).map_err(|e| format!("{}: {e}", output.display()))?;
    }
    prog.set(1.0);
    println!("{}: {:.1} s", input.file_name().map(|f| f.to_string_lossy()).unwrap_or_default(), p.duration);
    for s in summary {
        println!("  {s}");
    }
    if !a.keep_metadata {
        println!("  metadata removed (tags, chapters, location, dates, encoder)");
    }
    // the last line, exactly "wrote PATH": Minos reads the path from it
    println!("wrote {}", output.display());
    Ok(())
}

fn check_file(a: &Args) -> Result<(), String> {
    let input = absolute(&a.input)?;
    let p = probe(&input)?;
    if p.audio.is_empty() {
        return Err("the file has no sound".into());
    }
    let out = Command::new("ffmpeg")
        .args(["-nostdin", "-hide_banner", "-v", "error", "-i"])
        .arg(ff_path(&input))
        .args(["-map", "0:a:0", "-vn", "-f", "f32le", "-acodec", "pcm_f32le", "-ac", "1", "-ar", "8000", "pipe:1"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("ffmpeg could not be started ({e}); install ffmpeg"))?;
    if !out.status.success() {
        return Err(format!("decoding failed: {}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("")));
    }
    let x: Vec<f32> = out.stdout.chunks_exact(4).map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]])).collect();
    let cfg = Config::default();
    let ridges = detect_ridges(&x, 8000.0, &cfg, 8.0, 20.0, 0.01);
    let enf = detect_enf(&x, 8000.0);
    println!("{}: {:.1} s", input.file_name().map(|f| f.to_string_lossy()).unwrap_or_default(), x.len() as f64 / 8000.0);
    if ridges.is_empty() {
        println!("  no long gliding tones found");
    }
    for r in &ridges {
        println!(
            "  gliding tone {:.0}-{:.0} s, {:.1} -> {:.1} Hz, {:+.0} dB over the floor (aircraft, drone or traffic)",
            r.t_start, r.t_end, r.f_start, r.f_end, r.strength_db
        );
    }
    println!("  {}", enf.describe());
    println!("  note: lines under the noise floor are not found here, but a matched filter can still recover them: scrub");
    println!("  the copy you share whenever the place or the time matters.");
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if argv.iter().any(|a| a == "--version") {
        println!("heimdall-scrub {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let a = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("heimdall-scrub: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    let r = if a.check { check_file(&a) } else { scrub_file(&a) };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("heimdall-scrub: {e}");
            ExitCode::from(1)
        }
    }
}
