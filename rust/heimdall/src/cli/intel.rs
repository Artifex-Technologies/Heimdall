//! `heimdalld origin`, `ipdb-check`, `intel-check`, `kernel-check` (Go: cmd/heimdalld/origin.go, kernel.go) and the
//! `heimdall-intel-update` helper (packaging/arch/heimdall-intel-update).
//!
//! Not ported yet: every function answers None and the command goes to the Go binary (or, for a helper, stays the script).

pub fn origin(_args: &[String]) -> Option<i32> {
    None
}

pub fn ipdb_check(_args: &[String]) -> Option<i32> {
    None
}

pub fn intel_check(_args: &[String]) -> Option<i32> {
    None
}

pub fn kernel_check(_args: &[String]) -> Option<i32> {
    None
}

pub fn update_tool(_args: &[String]) -> Option<i32> {
    None
}
