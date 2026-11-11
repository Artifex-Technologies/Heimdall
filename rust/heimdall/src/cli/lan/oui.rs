//! Makers from hardware addresses (Go: internal/lan/oui.go): the IEEE's list of prefixes (Arch's hwdata package) and the
//! locally administered bit of made-up addresses.

use super::text::clean;
use std::collections::BTreeMap;
use std::io::BufRead;

/// The IEEE's list of hardware address prefixes and the companies they belong to.
pub const OUI_PATH: &str = "/usr/share/hwdata/oui.txt";

/// A locally administered hardware address: phones and computers make these up per network (Wi-Fi privacy), so the prefix
/// names no maker.
pub fn private_mac(mac: &str) -> bool {
    let b = mac.as_bytes();
    if b.len() < 2 {
        return false;
    }
    // Go walks the runes of the first two bytes lowercased: a non-hex rune adds nothing but still shifts
    let first: String = super::text::to_lower(&b[..2]);
    let mut v: u8 = 0;
    for c in first.chars() {
        v <<= 4;
        match c {
            '0'..='9' => v |= c as u8 - b'0',
            'a'..='f' => v |= c as u8 - b'a' + 10,
            _ => {}
        }
    }
    v & 0x02 != 0
}

/// The makers of the given addresses, in one pass over the list (only wanted prefixes are kept).
pub fn vendors(path: &str, macs: &[String]) -> BTreeMap<String, String> {
    let mut want: BTreeMap<String, Vec<&String>> = BTreeMap::new();
    for m in macs {
        if private_mac(m) || m.len() < 8 {
            continue;
        }
        // Go: strings.ToUpper(strings.ReplaceAll(m[:8], ":", "-")) on the first eight bytes
        let p = super::text::to_upper(
            m.as_bytes()[..8].to_vec().iter().map(|&b| if b == b':' { b'-' } else { b }).collect::<Vec<u8>>().as_slice(),
        );
        want.entry(p).or_default().push(m);
    }
    let mut out = BTreeMap::new();
    if want.is_empty() {
        return out;
    }
    let Ok(f) = std::fs::File::open(path) else { return out };
    // Go's bufio.Scanner: lines up to 64 KiB; a longer line ends the scan
    let mut r = std::io::BufReader::new(f);
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.len() >= 65536 {
            break;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.len() < 20 || line[2] != b'-' || super::text::index(&line[..20], b"(hex)").is_none() {
            continue;
        }
        let Ok(prefix) = std::str::from_utf8(&line[..8]) else { continue };
        if let Some(ms) = want.get(prefix) {
            let name = match super::text::index(&line, b"(hex)") {
                Some(i) => &line[i + 5..],
                None => &line[..0],
            };
            let v = short_vendor(&crate::gotext::lossy(name));
            for m in ms {
                out.insert((*m).clone(), v.clone());
            }
        }
    }
    out
}

/// A registered company name trimmed to what people call it ("Samsung Electronics Co.,Ltd" -> "Samsung Electronics").
pub fn short_vendor(s: &str) -> String {
    let mut s = clean(crate::gotext::trim_space(s).as_bytes());
    let upper: String = super::text::to_upper(s.as_bytes());
    if upper == s && s.len() > 4 {
        // "ASKEY COMPUTER CORP" -> "Askey Computer Corp": Go upper-cases the first byte of each word
        let lower = crate::gotext::to_lower(&s);
        let words: Vec<String> = crate::gotext::fields(&lower)
            .map(|w| {
                let b = w.as_bytes();
                let mut out = super::text::to_upper(&b[..1]);
                out.push_str(&crate::gotext::lossy(&b[1..]));
                out
            })
            .collect();
        s = words.join(" ");
    }
    for cut in [
        " Co.,Ltd",
        " Co., Ltd",
        " CO.,LTD",
        " Co.,Ltd.",
        ",",
        " Inc.",
        " Inc",
        " Corporation",
        " Corporate",
        " Corp.",
        " Corp",
        " Ltd.",
        " Ltd",
        " LLC",
        " GmbH",
        " Limited",
        " Technologies",
        " Technology",
        " International",
    ] {
        if let Some(i) = s.find(cut) {
            if i > 0 {
                s.truncate(i);
            }
        }
    }
    let t = s.trim_end_matches(['.', ' ']);
    crate::gotext::trim_space(t).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_go() {
        assert_eq!(short_vendor("ASKEY COMPUTER CORP"), "Askey Computer");
        assert_eq!(short_vendor("Intel Corporate"), "Intel");
        assert_eq!(short_vendor("Amazon Technologies Inc."), "Amazon");
        assert_eq!(short_vendor("Apple, Inc."), "Apple");
        assert!(private_mac("DA:BB:CC:00:00:01") && !private_mac("A8:BB:CC:00:00:01") && private_mac("02:00:00:00:00:00"));
    }
}
