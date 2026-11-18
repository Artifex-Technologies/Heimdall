//! A micro benchmark: how long loading the table takes and what one lookup costs, on this computer's files (hwdata, and the
//! IEEE folder when it is there). `cargo run --release -p heimdall-macvendor --example bench [IEEE_DIR [HWDATA_DIR]]`

use heimdall_macvendor::{DataPaths, Table};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut paths = DataPaths::default();
    if let Some(d) = args.next() {
        paths.ieee_dir = d.into();
    }
    if let Some(d) = args.next() {
        paths.hwdata_dir = d.into();
    }
    let t0 = Instant::now();
    let t = Table::load(&paths);
    let load = t0.elapsed();
    println!("loaded {} blocks in {:.1} ms", t.len(), load.as_secs_f64() * 1e3);
    for (reg, bits, n) in t.counts() {
        println!("  {:<4} {bits} bits: {n}", reg.name());
    }
    // addresses spread over the whole space (a fixed sequence, so runs compare), the local and group bits cleared so every
    // lookup goes through the registries
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let macs: Vec<[u8; 6]> = (0..1 << 16)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut m: [u8; 6] = std::array::from_fn(|i| (x >> (8 * i)) as u8);
            m[0] &= 0xfc;
            m
        })
        .collect();
    let rounds = 32;
    let mut found = 0usize;
    let t1 = Instant::now();
    for _ in 0..rounds {
        for m in &macs {
            if black_box(t.lookup(black_box(m))).vendor().is_some() {
                found += 1;
            }
        }
    }
    let per = t1.elapsed().as_secs_f64() * 1e9 / (rounds * macs.len()) as f64;
    println!("{:.0} ns per lookup ({} of {} found)", per, found / rounds, macs.len());
    // the process's memory: its peak includes reading the files, its current size the table kept
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for l in s.lines().filter(|l| l.starts_with("VmHWM") || l.starts_with("VmRSS")) {
            println!("{}", l.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
}
