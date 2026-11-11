//! `heimdalld remote list|approve|forget` (Go: cmd/heimdalld/main.go's runRemote, internal/remoteaccess): the remote-access
//! tools Heimdall knows, and the owner's approvals (/etc/heimdall/remote-access-approved.json), which make the daemon report
//! an approved tool as info instead of critical (docs/REMOTE_ACCESS.md).

use crate::gostruct::{self, Field, Ty, Val};
use crate::remoteaccess::Catalog;

/// The owner's approvals, as the daemon reads them.
pub const APPROVALS: &str = "/etc/heimdall/remote-access-approved.json";

static APPROVALS_FILE: Ty = Ty::Struct("struct", &[Field("approved", &Ty::Slice(&Ty::Str), false)]);

/// Go's SetApproved: the file read as far as it reads (a damaged one as empty), `id` added or removed, the list sorted
/// without repeats and written back (MarshalIndent with one space, a newline; a temporary file, then a rename). The list
/// written is returned; an error after it was made returns it too, as Go does.
pub fn set_approved(path: &str, id: &str, approve: bool) -> (Option<Vec<String>>, Result<(), String>) {
    let mut f = gostruct::zero(&APPROVALS_FILE);
    if let Ok(b) = std::fs::read(path) {
        // a syntax error leaves nothing read; a wrong type keeps what was read before and after it (Go's decoder)
        f = gostruct::unmarshal(&APPROVALS_FILE, &b).0;
    }
    let had = match &f {
        Val::Struct(v) => v[0].clone(),
        _ => Val::Slice(None),
    };
    let mut set: std::collections::BTreeSet<String> = match &had {
        Val::Slice(Some(items)) => items.iter().map(|x| if let Val::Str(s) = x { s.clone() } else { String::new() }).collect(),
        _ => Default::default(),
    };
    if approve {
        set.insert(id.to_string());
    } else {
        set.remove(id);
    }
    // Go: f.Approved = f.Approved[:0] keeps a nil list nil when nothing is left, and an empty one empty
    let list: Vec<String> = set.into_iter().collect();
    let approved = match (&had, list.is_empty()) {
        (Val::Slice(None), true) => Val::Slice(None),
        _ => Val::Slice(Some(list.iter().map(|s| Val::Str(s.clone())).collect())),
    };
    let body = gostruct::to_json_indented(&APPROVALS_FILE, &Val::Struct(vec![approved]), " ").unwrap_or_default() + "\n";
    let tmp = format!("{path}.tmp");
    if let Err(e) = crate::gopath::write_file(&tmp, body.as_bytes(), 0o644) {
        return (None, Err(e));
    }
    (Some(list), crate::gopath::rename(&tmp, path))
}

pub fn main(args: &[String]) -> Option<i32> {
    Some(run(args, APPROVALS))
}

fn run(args: &[String], path: &str) -> i32 {
    let c = Catalog::builtin();
    if args.is_empty() || args[0] == "list" {
        let approvals = crate::detect::Approvals::new(path);
        let mut out = String::new();
        for p in &c.providers {
            let mark = if approvals.approved(&p.id) { "*" } else { " " };
            out += &format!("{mark} {:<14} {:<15} {}\n", p.id, p.kind, p.name);
        }
        out += "(* approved: Heimdall reports it as info instead of critical)\n";
        print!("{out}");
        return 0;
    }
    if args.len() != 2 || (args[0] != "approve" && args[0] != "forget") {
        eprintln!("usage: heimdalld remote list | approve ID | forget ID");
        return 2;
    }
    if !rustix::process::geteuid().is_root() {
        eprintln!("heimdalld remote: approving needs root (sudo)");
        return 1;
    }
    let Some(p) = c.providers.iter().rev().find(|p| p.id == args[1]) else {
        eprintln!("heimdalld remote: no such tool (heimdalld remote list)");
        return 2;
    };
    if args[0] == "approve" && p.kind == "c2" {
        eprintln!("heimdalld remote: {} is a command-and-control implant and can never be approved", p.name);
        return 2;
    }
    match set_approved(path, &p.id, args[0] == "approve") {
        (_, Err(e)) => {
            eprintln!("heimdalld remote: {e}");
            1
        }
        (ids, Ok(())) => {
            println!("approved: {}", ids.unwrap_or_default().join(", "));
            0
        }
    }
}
