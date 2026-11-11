//! `heimdalld immunity ...` and `heimdalld scan-files` (Go: cmd/heimdalld/immunity.go, rules.go, main.go's cmdScanFiles,
//! internal/immunity, internal/scan).
//!
//! Not ported yet: every function answers None and the command goes to the Go binary (or, for a helper, stays the script).

pub fn main(_args: &[String]) -> Option<i32> {
    None
}

pub fn scan_files(_args: &[String]) -> Option<i32> {
    None
}
