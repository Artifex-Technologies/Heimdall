//! Who made a hardware (MAC) address, read offline from the IEEE's registries, and what an address is when no maker owns it.
//!
//! The IEEE hands out address blocks of three sizes: MA-L (the first 24 bits, the classic "OUI"), MA-M (28 bits) and MA-S
//! (36 bits; the older IAB blocks are 36 bits too). A small company's MA-S block sits inside a 24-bit block registered to
//! "IEEE Registration Authority", so the longest prefix wins: 36 bits, then 28, then 24.
//!
//! Before any registry is asked, an address is checked for what it says about itself:
//!
//! - well-known special addresses (broadcast, the IPv4 and IPv6 multicast ranges, the IEEE 802.1 link-local groups, VRRP and
//!   HSRP virtual routers, the documentation ranges of RFC 7042): [`Answer::Special`];
//! - any other group address (the first byte's lowest bit): [`Answer::Multicast`];
//! - a locally administered address (the first byte's second bit): [`Answer::Private`]. Phones, tablets and computers make
//!   these up per network (Wi-Fi privacy), so the prefix names no maker; it is never reported as a vendor.
//!
//! The data is IEEE's only: Arch's hwdata package (`/usr/share/hwdata/oui.txt` and `iab.txt`) by default, and the IEEE's own
//! CSV files (`oui.csv`, `mam.csv`, `oui36.csv`, `iab.csv`) when they are in [`IEEE_DIR`]. No other project's list.
//!
//! The table is loaded once, on the first lookup ([`global`]), into a few sorted arrays with every name stored once; a lookup
//! is three binary searches and allocates nothing.
//!
//! Heimdall's Go build has a twin of this crate (`internal/macvendor`) that gives the same answers on the same files
//! (`testdata/parity/macvendor.json`).

pub mod fuzzing;
mod name;
mod special;
mod table;

pub use name::{clean, short};
pub use special::Special;
pub use table::{Builder, Table};

use std::path::PathBuf;
use std::sync::OnceLock;

/// A hardware address, six bytes.
pub type Mac = [u8; 6];

/// Where the IEEE's own files go when they are downloaded (not done yet: see Heimdall's docs/DEVICES.md, "Vendor data"). A
/// folder of its own, readable by everyone, because Heimdall's /var/lib/heimdall is closed to other accounts and Settings
/// reads these files as the person signed in.
pub const IEEE_DIR: &str = "/var/lib/heimdall-ieee";

/// Arch's hwdata package: the IEEE's MA-L and IAB lists as text.
pub const HWDATA_DIR: &str = "/usr/share/hwdata";

/// The IEEE registry an answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Registry {
    /// MA-L, large blocks: the first 24 bits (the classic OUI).
    MaL,
    /// MA-M, medium blocks: 28 bits.
    MaM,
    /// MA-S, small blocks: 36 bits.
    MaS,
    /// IAB, the older individual address blocks: 36 bits, no longer handed out.
    Iab,
}

impl Registry {
    /// The IEEE's own name for it ("MA-L", "MA-M", "MA-S", "IAB").
    pub fn name(self) -> &'static str {
        match self {
            Registry::MaL => "MA-L",
            Registry::MaM => "MA-M",
            Registry::MaS => "MA-S",
            Registry::Iab => "IAB",
        }
    }

    /// The registry with this name (the CSV files' first column), in any case.
    pub fn from_name(s: &str) -> Option<Registry> {
        let s = s.trim_matches(|c| c == ' ' || c == '\t');
        [Registry::MaL, Registry::MaM, Registry::MaS, Registry::Iab].into_iter().find(|r| r.name().eq_ignore_ascii_case(s))
    }
}

/// A registered maker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vendor<'t> {
    /// The name as registered, cleaned (no control or invisible characters, single spaces, at most 128 bytes).
    pub name: &'t str,
    /// What people call it ("Samsung Electronics Co.,Ltd" -> "Samsung Electronics"): [`short`].
    pub short: &'t str,
    /// The registry the block is in.
    pub registry: Registry,
    /// How many leading bits the block covers (24, 28 or 36).
    pub bits: u8,
}

/// What an address is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'t> {
    /// A maker's block.
    Vendor(Vendor<'t>),
    /// A well-known special address (broadcast, a multicast range, a virtual router, documentation).
    Special(&'static Special),
    /// Another group (multicast) address.
    Multicast,
    /// A locally administered address: made up by the device (Wi-Fi privacy) or by an administrator; it names no maker.
    Private,
    /// A globally unique address in no registry that was loaded.
    Unknown,
    /// Not a hardware address.
    Invalid,
}

impl<'t> Answer<'t> {
    /// A short word for the kind of answer: vendor, special, multicast, private, unknown or invalid.
    pub fn kind(&self) -> &'static str {
        match self {
            Answer::Vendor(_) => "vendor",
            Answer::Special(_) => "special",
            Answer::Multicast => "multicast",
            Answer::Private => "private",
            Answer::Unknown => "unknown",
            Answer::Invalid => "invalid",
        }
    }

    /// The name to show beside the address: the maker's short name or the special address's short name; empty otherwise.
    pub fn label(&self) -> &'t str {
        match self {
            Answer::Vendor(v) => v.short,
            Answer::Special(s) => s.short,
            _ => "",
        }
    }

    /// The maker, when the address is in a registry.
    pub fn vendor(&self) -> Option<Vendor<'t>> {
        match self {
            Answer::Vendor(v) => Some(*v),
            _ => None,
        }
    }
}

/// The first byte's lowest bit: a group (multicast or broadcast) address.
pub fn is_multicast(mac: &Mac) -> bool {
    mac[0] & 0x01 != 0
}

/// The first byte's second bit: a locally administered address (made up, not a maker's).
pub fn is_local(mac: &Mac) -> bool {
    mac[0] & 0x02 != 0
}

/// Reads a hardware address: six pairs of hex digits split by `:` or `-` ("00:11:22:aa:bb:cc"), Cisco's three groups of four
/// split by `.` ("0011.22aa.bbcc"), or twelve hex digits. Spaces and tabs around it are ignored; anything else is not an
/// address.
pub fn parse_mac(s: &str) -> Option<Mac> {
    let b = s.trim_matches(|c| c == ' ' || c == '\t').as_bytes();
    let mut digits = [0u8; 12];
    let mut n = 0;
    let ok = match b.len() {
        17 => b.iter().enumerate().all(|(i, &c)| {
            if i % 3 == 2 {
                // one kind of separator throughout
                (c == b':' || c == b'-') && c == b[2]
            } else {
                push_hex(c, &mut digits, &mut n)
            }
        }),
        14 => b.iter().enumerate().all(|(i, &c)| if i % 5 == 4 { c == b'.' } else { push_hex(c, &mut digits, &mut n) }),
        12 => b.iter().all(|&c| push_hex(c, &mut digits, &mut n)),
        _ => false,
    };
    if !ok || n != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        *m = digits[2 * i] << 4 | digits[2 * i + 1];
    }
    Some(mac)
}

fn push_hex(c: u8, digits: &mut [u8; 12], n: &mut usize) -> bool {
    let Some(v) = hex_value(c) else { return false };
    if *n >= 12 {
        return false;
    }
    digits[*n] = v;
    *n += 1;
    true
}

pub(crate) fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The address as one number, the first byte highest.
pub(crate) fn mac_value(mac: &Mac) -> u64 {
    mac.iter().fold(0u64, |v, &b| v << 8 | b as u64)
}

/// Where the table's files are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPaths {
    /// The IEEE's own files (`oui.csv`, `mam.csv`, `oui36.csv`, `iab.csv`; the `.txt` forms are read too).
    pub ieee_dir: PathBuf,
    /// Arch's hwdata (`oui.txt`, `iab.txt`), used for a registry the IEEE folder has no usable file for.
    pub hwdata_dir: PathBuf,
}

impl Default for DataPaths {
    fn default() -> Self {
        DataPaths { ieee_dir: PathBuf::from(IEEE_DIR), hwdata_dir: PathBuf::from(HWDATA_DIR) }
    }
}

/// The table from the files on this computer ([`DataPaths::default`]), loaded on the first call and kept for the life of the
/// program. A program that wants to load it off its main thread calls this once early.
pub fn global() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| Table::load(&DataPaths::default()))
}

/// [`Table::lookup`] in the [`global`] table.
pub fn lookup(mac: &Mac) -> Answer<'static> {
    global().lookup(mac)
}

/// [`Table::lookup_str`] in the [`global`] table.
pub fn lookup_str(mac: &str) -> Answer<'static> {
    global().lookup_str(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_read_in_the_usual_forms_only() {
        let want = Some([0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
        for s in ["00:11:22:aa:bb:cc", "00-11-22-AA-BB-CC", "0011.22aa.bbcc", "001122AABBCC", " 00:11:22:aa:bb:cc\t"] {
            assert_eq!(parse_mac(s), want, "{s}");
        }
        for s in [
            "",
            "0",
            "00:11:22:aa:bb",
            "00:11:22:aa:bb:cc:dd",
            "00:11-22:aa:bb:cc",
            "0:11:22:aa:bb:cc",
            "00:11:22:aa:bb:cg",
            "00 11 22 aa bb cc",
            "0011.22aa.bbc",
            "0011:22aa:bbcc",
            "001122aabbc",
            "00:11:22:aa:bb:c\u{e9}",
            "\u{ff10}0:11:22:aa:bb:cc",
            "+0:11:22:aa:bb:cc",
            "00:11:22:aa:bb:cc\n",
        ] {
            assert_eq!(parse_mac(s), None, "{s:?}");
        }
    }

    #[test]
    fn registries_by_name() {
        assert_eq!(Registry::from_name("ma-l"), Some(Registry::MaL));
        assert_eq!(Registry::from_name(" IAB "), Some(Registry::Iab));
        assert_eq!(Registry::from_name("CID"), None);
        assert_eq!(Registry::MaS.name(), "MA-S");
    }
}
