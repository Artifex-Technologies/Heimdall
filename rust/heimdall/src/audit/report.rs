//! What GET /v1/audit answers (Go: internal/auditreport): everything open now, computed on each request from the files the
//! audits read: the installed packages' known holes, each installed kernel's holes (the 15 worst), the hardening gaps, and
//! which lists are not downloaded yet.

use super::{hardening, kernel, pkg};
use crate::gojson::{self, ObjectWriter};
use crate::gotext;

/// Where the report reads (Go: auditreport.Computer).
#[derive(Clone, Debug, Default)]
pub struct Computer {
    pub tracker: String,
    pub pacman_db: String,
    pub kernel_vulns: String,
    pub modules: String,
    /// The running kernel's name; None: ask the kernel (uname).
    pub running: Option<String>,
    pub hardening_root: String,
}

fn strings(out: &mut String, v: Option<&[String]>) {
    match v {
        None => out.push_str("null"),
        Some(items) => {
            out.push('[');
            for (i, s) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                gojson::write_str(out, s);
            }
            out.push(']');
        }
    }
}

struct Kernel {
    running: bool,
    json: String,
}

/// The report as Go's encoder writes it (without the final newline).
pub fn build(c: &Computer) -> String {
    let mut missing: Vec<&str> = Vec::new();
    let mut packages: Option<String> = None;
    match pkg::load_tracker(&c.tracker) {
        Err(_) => missing.push("the package security tracker"),
        Ok(groups) => {
            if let Ok(inst) = pkg::installed(&c.pacman_db) {
                let found = pkg::check(&groups, &inst);
                if !found.is_empty() {
                    let mut b = String::from("[");
                    for (i, f) in found.iter().enumerate() {
                        if i > 0 {
                            b.push(',');
                        }
                        let mut o = ObjectWriter::new(&mut b);
                        o.str("package", &f.package);
                        o.str("installed", &gotext::lossy(&f.installed));
                        if !f.no_fix && !f.group.fixed.is_empty() {
                            o.str("fixed", &f.group.fixed);
                        }
                        o.str("severity", &f.group.severity);
                        o.str("advisory", &f.group.name);
                        strings(o.key("cves"), f.group.issues.as_deref());
                        o.str("type", &f.group.type_);
                        o.end();
                    }
                    b.push(']');
                    packages = Some(b);
                }
            }
        }
    }
    let mut kernels: Vec<Kernel> = Vec::new();
    match kernel::load(&c.kernel_vulns) {
        Err(_) => missing.push("the kernel CVE list"),
        Ok(list) => {
            let running = c.running.clone().unwrap_or_else(kernel::running);
            let (y, m, d, ..) = list.generated.civil();
            let date = format!("{y:04}-{m:02}-{d:02}");
            for k in kernel::installed(&c.modules) {
                let (holes, fix) = kernel::check(&list, &k);
                let mut b = String::new();
                let mut o = ObjectWriter::new(&mut b);
                o.str("kernel", &k);
                o.raw("running", if k == running { "true" } else { "false" });
                o.raw("count", &holes.len().to_string());
                if !fix.is_empty() {
                    o.str("fixed_all_in", &fix);
                }
                let w = o.key("worst");
                if holes.is_empty() {
                    w.push_str("null");
                } else {
                    w.push('[');
                    for (i, h) in holes.iter().take(15).enumerate() {
                        if i > 0 {
                            w.push(',');
                        }
                        let mut ho = ObjectWriter::new(w);
                        ho.str("id", &h.vuln.id);
                        if h.vuln.score != 0.0 {
                            gojson::write_f64(ho.key("score"), h.vuln.score);
                        }
                        ho.str("fixed_in", &h.fixed_in);
                        ho.raw("same_line", if h.same_line { "true" } else { "false" });
                        if h.vuln.exploited {
                            ho.raw("exploited", "true");
                        }
                        ho.str("summary", &h.vuln.summary);
                        ho.end();
                    }
                    w.push(']');
                }
                o.str("list_date", &date);
                o.end();
                kernels.push(Kernel { running: k == running, json: b });
            }
            // Go: sort.Slice, the running kernel first (stable at these sizes: insertion sort below 12)
            kernels.sort_by_key(|k| !k.running);
        }
    }
    let gaps = hardening::System { root: c.hardening_root.clone() }.check();
    let mut out = String::new();
    let mut o = ObjectWriter::new(&mut out);
    o.raw("packages", packages.as_deref().unwrap_or("null"));
    let ks = o.key("kernels");
    if kernels.is_empty() {
        ks.push_str("null");
    } else {
        ks.push('[');
        for (i, k) in kernels.iter().enumerate() {
            if i > 0 {
                ks.push(',');
            }
            ks.push_str(&k.json);
        }
        ks.push(']');
    }
    let hs = o.key("hardening");
    if gaps.is_empty() {
        hs.push_str("null");
    } else {
        hs.push('[');
        for (i, g) in gaps.iter().enumerate() {
            if i > 0 {
                hs.push(',');
            }
            let mut go = ObjectWriter::new(hs);
            go.str("id", &g.id);
            go.str("now", &g.now);
            go.str("why", &g.why);
            go.str("fix", &g.fix);
            go.str("level", &g.level);
            go.end();
        }
        hs.push(']');
    }
    if !missing.is_empty() {
        let m: Vec<String> = missing.iter().map(|s| s.to_string()).collect();
        strings(o.key("missing"), Some(&m));
    }
    o.end();
    out
}
