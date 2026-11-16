//! heimdall-multilink: several internet connections at once (docs/MULTILINK.md).
//!
//! New connections of this computer's own programs are spread over the links I pick (Wi-Fi, Ethernet, a phone over USB)
//! by the kernel's own multipath routing: no tunnel, no packet passes through this program. Each connection stays on the
//! link it started on. This program only looks after the routing: it checks each link, weighs them by what they carried,
//! and keeps a set of rules and routes of its own (plan.rs) beside NetworkManager's, which it never changes.

pub mod config;
pub mod ipjson;
pub mod plan;
pub mod probe;
pub mod service;
pub mod sys;
pub mod usage;
pub mod weights;
