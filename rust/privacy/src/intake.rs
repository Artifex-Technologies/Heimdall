//! Safe file intake: the extraction in its sandboxed process (`extract-worker`, see sandbox.rs), the command `extract` around
//! it (a new folder, the files written, each one checked by `scan`, everything removed on a refusal), and the waits with a
//! time limit both use. docs/PRIVACY_PACK.md, "Safe file intake".

use crate::extract::{self, Compression, Format, Options, Outcome, Refusal, Why};
use crate::{clamav, lookalike, sandbox, scan};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// What a child printed, and whether it was stopped for taking too long.
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: Option<std::process::ExitStatus>,
    pub timed_out: bool,
}

/// Waits for a child (its output read as it comes, 32 MiB of each at most), killing it after `limit`.
pub fn wait_output(mut child: Child, limit: Duration) -> Output {
    fn drain<R: Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut v = vec![];
            if let Some(r) = r {
                let mut r = r.take(32 << 20);
                let _ = r.read_to_end(&mut v);
                // what is over the cap is read and dropped, so the child never blocks on a full pipe
                let _ = std::io::copy(&mut r.into_inner(), &mut std::io::sink());
            }
            v
        })
    }
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let end = Instant::now() + limit;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Err(_) => break None,
        }
    };
    Output { stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default(), status, timed_out }
}

// ---- the engine on an open file ----

/// The decompressors run as programs (inside the sandbox, which lets it run what is under /usr), each with a memory limit.
fn decompressor(c: Compression, file: std::fs::File) -> Result<(Box<dyn Read>, Option<Child>), Refusal> {
    let (prog, args): (&str, &[&str]) = match c {
        Compression::None => return Ok((Box::new(std::io::BufReader::with_capacity(64 << 10, file)), None)),
        Compression::Gzip => {
            return Ok((Box::new(flate2::read::MultiGzDecoder::new(std::io::BufReader::with_capacity(64 << 10, file))), None))
        }
        Compression::Xz => ("/usr/bin/xz", &["-dcq", "--memlimit=256MiB"]),
        Compression::Zstd => ("/usr/bin/zstd", &["-dcq", "--memory=256MB"]),
        Compression::Bzip2 => ("/usr/bin/bzip2", &["-dcq"]),
    };
    let name = prog.rsplit('/').next().unwrap_or(prog);
    if !Path::new(prog).is_file() {
        return Err(Refusal { why: Why::Unsupported, reason: format!("{name} is not installed, so this archive cannot be opened") });
    }
    // no /dev/null inside the sandbox: standard error is the caller's
    let mut child = Command::new(prog)
        .args(args)
        .env_clear()
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| Refusal { why: Why::Unsupported, reason: format!("{name} could not start: {e}") })?;
    let out = child.stdout.take().ok_or_else(|| Refusal { why: Why::Unsupported, reason: format!("{name} could not start") })?;
    Ok((Box::new(std::io::BufReader::with_capacity(64 << 10, out)), Some(child)))
}

/// Runs the extraction (or the dry run with extract::Discard) on an archive already open.
pub fn engine(file: std::fs::File, name: &str, fmt: Format, o: &Options, sink: &mut dyn extract::Sink) -> Outcome {
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    match fmt {
        Format::Zip => extract::zip(&file, o, sink),
        Format::Tar(c) => {
            let (mut r, child) = match decompressor(c, file) {
                Ok(x) => x,
                Err(e) => return Outcome { refused: Some(e), ..Outcome::default() },
            };
            let mut out = extract::stream(&mut r, size, &extract::single_name(name), c != Compression::None, o, sink);
            drop(r);
            if let Some(mut ch) = child {
                // stopped early (the tar's end, or a refusal): it dies of a closed pipe, which is fine; an exit code of its
                // own means it found the data damaged (or over its memory limit)
                if let Ok(st) = ch.wait() {
                    if out.refused.is_none() && st.code().is_some_and(|c| c != 0) {
                        out.refused = Some(Refusal {
                            why: Why::Damaged,
                            reason: "it is damaged, or would need more than 256 MiB of memory to unpack".into(),
                        });
                    }
                }
            }
            out
        }
    }
}

/// Opens an archive for reading: a regular file only (never blocking on a FIFO).
pub fn open_archive(p: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open(p)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// The kind of an open archive from its first bytes.
pub fn kind_of(f: &std::fs::File) -> Result<Option<Format>, &'static str> {
    let len = f.metadata().map(|m| m.len()).unwrap_or(0).min(512) as usize;
    let mut head = vec![0u8; len];
    if crate::zip::Source::read_at(f, 0, &mut head).is_err() {
        return Ok(None);
    }
    extract::detect(&head)
}

// ---- the worker (the sandboxed process) ----

fn outcome_json(o: &Outcome) -> Value {
    json!({
        "files": o.files.iter().map(|f| json!({"name": f.name, "path": f.path, "size": f.size})).collect::<Vec<_>>(),
        "skipped": o.skipped.iter().map(|s| json!({"name": s.name, "reason": s.reason})).collect::<Vec<_>>(),
        "refused": o.refused.as_ref().map(|r| json!({"why": r.why.id(), "reason": r.reason})),
        "unpacked": o.unpacked,
    })
}

fn outcome_from(v: &Value) -> Option<Outcome> {
    let s = |x: &Value, k: &str| x.get(k).and_then(Value::as_str).map(str::to_string);
    let files = v.get("files")?.as_array()?;
    let skipped = v.get("skipped")?.as_array()?;
    Some(Outcome {
        files: files
            .iter()
            .map(|f| Some(extract::Written { name: s(f, "name")?, path: s(f, "path")?, size: f.get("size")?.as_u64()? }))
            .collect::<Option<Vec<_>>>()?,
        skipped: skipped
            .iter()
            .map(|k| Some(extract::Skipped { name: s(k, "name")?, reason: s(k, "reason")? }))
            .collect::<Option<Vec<_>>>()?,
        refused: match v.get("refused") {
            Some(Value::Null) | None => None,
            Some(r) => Some(Refusal { why: Why::from_id(r.get("why")?.as_str()?), reason: s(r, "reason")? }),
        },
        unpacked: v.get("unpacked").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// `extract-worker [--dry-run] [--only EXT,EXT] -- ARCHIVE [OUTDIR]`: the process `extract` and `scan` start. It opens the
/// archive and the folder, shuts itself in (sandbox::confine), extracts, and prints one JSON line.
pub fn worker_main(args: &[String]) -> i32 {
    let mut dry = false;
    let mut only = vec![];
    let mut rest: Vec<&String> = vec![];
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry = true,
            "--only" if i + 1 < args.len() => {
                only = split_only(&args[i + 1]);
                i += 1;
            }
            "--" => {
                rest.extend(&args[i + 1..]);
                break;
            }
            _ => rest.push(&args[i]),
        }
        i += 1;
    }
    let (archive, outdir) = match (rest.first(), rest.get(1), dry) {
        (Some(a), None, true) => (PathBuf::from(a), None),
        (Some(a), Some(o), false) => (PathBuf::from(a), Some(PathBuf::from(o))),
        _ => return 2,
    };
    let print = |o: &Outcome| println!("{}", outcome_json(o));
    let refuse = |why: Why, reason: String| Outcome { refused: Some(Refusal { why, reason }), ..Outcome::default() };
    let file = match open_archive(&archive) {
        Ok(f) => f,
        Err(e) => {
            print(&refuse(Why::Damaged, format!("it could not be read: {e}")));
            return 0;
        }
    };
    let fmt = match kind_of(&file) {
        Ok(Some(f)) => f,
        Ok(None) => {
            print(&refuse(Why::Unsupported, "it is not an archive Heimdall can open".into()));
            return 0;
        }
        Err(k) => {
            print(&refuse(Why::Unsupported, format!("Heimdall does not open {k} archives")));
            return 0;
        }
    };
    let mut disk = match &outdir {
        Some(o) => match extract::Disk::open(o) {
            Ok(d) => Some(d),
            Err(e) => {
                print(&refuse(Why::Write, format!("the folder could not be opened: {e}")));
                return 0;
            }
        },
        None => None,
    };
    // a file over the per-file limit makes write() fail with EFBIG instead of killing the process
    // SAFETY: setting a signal's disposition to ignore
    unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
    let rep = sandbox::confine(outdir.as_deref());
    if rep.landlock == 0 {
        eprintln!("heimdall-fileguard: Landlock is not available on this kernel; unpacking under the limits only");
    }
    let name = archive.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let o = Options { only, limits: extract::Limits::default() };
    let out = match disk.as_mut() {
        Some(d) => engine(file, &name, fmt, &o, d),
        None => engine(file, &name, fmt, &o, &mut extract::Discard),
    };
    print(&out);
    0
}

/// "ttf, .OTF ,woff2" -> ["ttf", "otf", "woff2"].
pub fn split_only(s: &str) -> Vec<String> {
    s.split(',').map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase()).filter(|e| !e.is_empty()).collect()
}

/// Runs the worker and reads its answer; a worker that crashed, ran out of memory or time is a refusal.
pub fn run_worker(exe: &Path, archive: &Path, outdir: Option<&Path>, only: &[String]) -> Outcome {
    let mut cmd = Command::new(exe);
    cmd.arg("extract-worker");
    if outdir.is_none() {
        cmd.arg("--dry-run");
    }
    if !only.is_empty() {
        cmd.arg("--only").arg(only.join(","));
    }
    cmd.arg("--").arg(archive);
    if let Some(o) = outdir {
        cmd.arg(o);
    }
    cmd.env_clear().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    // SAFETY: setrlimit only, in the child before exec
    unsafe { std::os::unix::process::CommandExt::pre_exec(&mut cmd, sandbox::limits(extract::Limits::default().per_file)) };
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Outcome {
                refused: Some(Refusal { why: Why::Write, reason: format!("the sandboxed check could not start: {e}") }),
                ..Outcome::default()
            }
        }
    };
    let out = wait_output(child, Duration::from_secs(300));
    let parsed = serde_json::from_slice::<Value>(&out.stdout).ok().and_then(|v| outcome_from(&v));
    match parsed {
        Some(o) if out.status.is_some_and(|s| s.success()) => o,
        _ => {
            let how = if out.timed_out {
                "it took too long".to_string()
            } else {
                match out.status.map(|s| (s.code(), std::os::unix::process::ExitStatusExt::signal(&s))) {
                    Some((_, Some(sig))) if sig == libc::SIGKILL || sig == libc::SIGXCPU => "it needed too much time or memory".into(),
                    Some((_, Some(_))) | None => "it ran out of memory or crashed".into(),
                    Some((c, None)) => format!("exit {}", c.unwrap_or(-1)),
                }
            };
            Outcome {
                refused: Some(Refusal { why: Why::Bomb, reason: format!("the archive could not be unpacked safely ({how})") }),
                ..Outcome::default()
            }
        }
    }
}

// ---- the command ----

/// The answer of `extract`: printed as JSON or as text.
pub struct Extracted {
    pub files: Vec<(extract::Written, PathBuf, scan::Checked)>,
    pub skipped: Vec<extract::Skipped>,
    pub refused: Option<String>,
    /// A usage or reading error (exit 2).
    pub error: bool,
}

impl Extracted {
    fn fail(msg: String) -> Extracted {
        Extracted { files: vec![], skipped: vec![], refused: Some(msg), error: true }
    }

    pub fn json(&self) -> Value {
        json!({
            "files": self.files.iter().map(|(w, p, c)| json!({
                "name": w.name, "path": p.display().to_string(), "size": w.size,
                "verdict": c.verdict.id(), "reasons": c.reasons, "clamav": c.clamav.id(),
            })).collect::<Vec<_>>(),
            "skipped": self.skipped.iter().map(|s| json!({"name": s.name, "reason": s.reason})).collect::<Vec<_>>(),
            "refused": self.refused,
        })
    }

    pub fn code(&self) -> i32 {
        if self.error {
            2
        } else if self.refused.is_some() {
            1
        } else {
            0
        }
    }
}

/// `extract`: OUTDIR must not exist; it is made (0700), the archive unpacked into it by the sandboxed worker, and each
/// file checked by `scan` (ClamAV included). On a refusal everything written is removed, OUTDIR too.
pub fn extract_command(exe: &Path, archive: &Path, outdir: &Path, only: &[String], scanner: &clamav::Scanner) -> Extracted {
    if let Err(e) = open_archive(archive) {
        return Extracted::fail(format!("{}: {e}", lookalike::visible(&archive.display().to_string())));
    }
    if std::fs::symlink_metadata(outdir).is_ok() {
        return Extracted::fail(format!("{} already exists; give a new folder", lookalike::visible(&outdir.display().to_string())));
    }
    if let Err(e) = std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700).create(outdir) {
        return Extracted::fail(format!("{} could not be made: {e}", lookalike::visible(&outdir.display().to_string())));
    }
    let _ = std::fs::set_permissions(outdir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let root = std::fs::canonicalize(outdir).unwrap_or_else(|_| outdir.to_path_buf());
    let remove = || {
        let _ = std::fs::remove_dir_all(&root);
    };
    let out = run_worker(exe, archive, Some(&root), only);
    if let Some(r) = out.refused {
        remove();
        return Extracted { files: vec![], skipped: out.skipped, refused: Some(r.reason), error: false };
    }
    let paths: Vec<PathBuf> = out.files.iter().map(|w| root.join(&w.path)).collect();
    let checked = scan::scan(&paths, &scan::Settings { worker: Some(exe.to_path_buf()), archives: true }, scanner);
    let error = checked.iter().any(|c| c.error);
    let refused = checked
        .iter()
        .zip(&out.files)
        .find(|(c, _)| c.verdict == scan::Verdict::Refused)
        .map(|(c, w)| format!("{}: {}", w.name, c.reasons.first().cloned().unwrap_or_default()));
    if refused.is_some() || error {
        remove();
    }
    let files = out.files.into_iter().zip(paths).zip(checked).map(|((w, p), c)| (w, p, c)).collect();
    Extracted { files, skipped: out.skipped, refused, error }
}
