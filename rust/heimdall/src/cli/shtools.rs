//! The programs the package shipped as shell scripts, ported to Rust: `heimdall-intel-update` (the daily downloads of
//! threat lists, the security tracker, the kernel's CVE list and the IP databases), `heimdall-dns-blocklist` (the DNS block
//! list), `heimdall-enable-defaults` (the first-install hook) and NetworkManager's dispatcher `91-heimdall-netid`. This
//! program answers to their names (`cli::tool`), so at the switch each becomes a link to it, like the Wi-Fi helpers.
//!
//! Each does what its script did: the same arguments, environment, files, modes, output, exit codes and network requests,
//! the text tools' steps (`coreutils.rs`, `gunzip.rs`) and curl's download (`fetch.rs`) carried over, proved by running
//! both on the same made-up systems with stand-in servers on loopback (tests/cli_shtools.rs, docs/RUST_CLI.md).

pub mod coreutils;
pub mod dnsblock;
pub mod enable_defaults;
pub mod fetch;
pub mod gunzip;
pub mod intel_update;
pub mod netid;
