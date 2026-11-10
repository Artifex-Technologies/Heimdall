//! How much memory the rules take: RSS before and after compiling them, and after a search with each.
//!     cargo run --release --example memprobe
fn rss() -> String {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines().filter(|l| l.starts_with("VmRSS") || l.starts_with("VmHWM") || l.starts_with("RssAnon")).collect::<Vec<_>>().join("  ")
}

fn main() {
    println!("start:    {}", rss());
    heimdall::rules::check_builtin().unwrap();
    println!("compiled: {}", rss());
    let text = "the build finished and I checked the log file for errors; nothing stood out ".repeat(50);
    for r in &heimdall::rules::builtin().rules {
        let _ = r.re.is_match(&text);
    }
    println!("searched: {}", rss());
}
