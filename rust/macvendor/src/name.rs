//! Company names as registered, made safe to show (`clean`), and as people say them (`short`). Go: internal/macvendor/name.go;
//! both work on bytes and on a fixed list of characters, so the two give the same answer on any input.

/// The longest name kept, in bytes.
pub const MAX_NAME: usize = 128;

/// A registered name made safe to show: bytes that are not UTF-8 make the whole name read byte by byte (each byte above 0x7F
/// becomes U+FFFD); control, invisible and direction-changing characters are dropped; runs of spaces (any kind) become one;
/// no space at either end; at most [`MAX_NAME`] bytes, cut at a character.
pub fn clean(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) => clean_chars(s.chars()),
        Err(_) => clean_chars(raw.iter().map(|&b| if b < 0x80 { b as char } else { '\u{fffd}' })),
    }
}

fn clean_chars(chars: impl Iterator<Item = char>) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in chars {
        if is_space(c) {
            space = true;
            continue;
        }
        if is_dropped(c) {
            continue;
        }
        let need = c.len_utf8() + usize::from(space && !out.is_empty());
        if out.len() + need > MAX_NAME {
            break;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(c);
    }
    out
}

/// Spaces of every kind (they become one ASCII space).
pub(crate) fn is_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// Control, invisible and direction-changing characters: dropped, so a registered name cannot hide or reorder text.
pub(crate) fn is_dropped(c: char) -> bool {
    matches!(c,
        '\u{00}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{ad}' | '\u{34f}' | '\u{61c}' | '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}'
        | '\u{180b}'..='\u{180f}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{3164}'
        | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}' | '\u{fff0}'..='\u{fffb}' | '\u{e0000}'..='\u{e0fff}')
}

/// Company endings cut from the short name, matched in any case, those ending in a letter as whole words only (" Inc" but
/// not the "Inc" of "Incom"). Tried in this order; the first place each matches (never at the very start) ends the name.
const CUTS: &[&str] = &[
    " co.,ltd",
    " co., ltd",
    " co.ltd",
    " co ltd",
    ",",
    " incorporated",
    " inc.",
    " inc",
    " corporation",
    " corporate",
    " corp.",
    " corp",
    " co.",
    " ltd.",
    " ltd",
    " llc",
    " gmbh",
    " ag",
    " s.a.",
    " b.v.",
    " pte",
    " pty",
    " limited",
    " technologies",
    " technology",
    " international",
];

/// What people call a company ("Samsung Electronics Co.,Ltd" -> "Samsung Electronics", "ASKEY COMPUTER CORP" -> "Askey
/// Computer", "Intel Corporate" -> "Intel"). Takes a cleaned name. A name in capitals only (ASCII; more than 4 bytes) is
/// written with a capital per word, words of up to 3 letters (LG, ZTE) staying as they are; then company endings are cut and
/// trailing dots, commas, dashes and spaces removed. Never empty for a non-empty name.
pub fn short(full: &str) -> String {
    let b = full.as_bytes();
    let mut s: Vec<u8> = b.to_vec();
    if b.len() > 4 && b.iter().any(u8::is_ascii_uppercase) && !b.iter().any(u8::is_ascii_lowercase) {
        let mut start = 0;
        for i in 0..=s.len() {
            if i == s.len() || s[i] == b' ' {
                if i - start > 3 {
                    s[start + 1..i].make_ascii_lowercase();
                }
                start = i + 1;
            }
        }
    }
    for cut in CUTS {
        if let Some(i) = find_word(&s, cut.as_bytes()) {
            s.truncate(i);
        }
    }
    while let Some(&last) = s.last() {
        if matches!(last, b' ' | b'.' | b',' | b'-') {
            s.pop();
        } else {
            break;
        }
    }
    if s.is_empty() {
        return full.to_string();
    }
    // only ASCII bytes were changed or cut before an ASCII byte, so this is still UTF-8
    String::from_utf8(s).unwrap_or_else(|_| full.to_string())
}

/// The first place after the start where `cut` matches in any ASCII case and, when it ends in a letter or digit, is not
/// followed by another.
fn find_word(s: &[u8], cut: &[u8]) -> Option<usize> {
    let word = cut.last().is_some_and(u8::is_ascii_alphanumeric);
    (1..s.len()).find(|&i| {
        s.len() - i >= cut.len()
            && s[i..i + cut.len()].eq_ignore_ascii_case(cut)
            && !(word && s.get(i + cut.len()).is_some_and(u8::is_ascii_alphanumeric))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean(b"  Example\t\tNetworks \r\n"), "Example Networks");
        assert_eq!(clean("A\u{202e}B\u{200b}C\u{feff}D\u{0}E\u{85}F".as_bytes()), "ABCDEF");
        assert_eq!(clean("Caf\u{e9}\u{a0}\u{3000}Bar".as_bytes()), "Caf\u{e9} Bar");
        // not UTF-8: read byte by byte
        assert_eq!(clean(b"Ecole \xc9lectronique"), "Ecole \u{fffd}lectronique");
        assert_eq!(clean(b""), "");
        assert_eq!(clean(b" \t\x01 "), "");
        let long = "\u{e9}".repeat(100);
        let c = clean(long.as_bytes());
        assert_eq!(c.len(), 128);
        assert!(clean(format!("{} x", "a".repeat(127)).as_bytes()).len() == 127);
    }

    #[test]
    fn short_names() {
        for (full, want) in [
            ("ASKEY COMPUTER CORP", "Askey Computer"),
            ("Intel Corporate", "Intel"),
            ("Amazon Technologies Inc.", "Amazon"),
            ("Apple, Inc.", "Apple"),
            ("Samsung Electronics Co.,Ltd", "Samsung Electronics"),
            ("Nokia Shanghai Bell Co., Ltd.", "Nokia Shanghai Bell"),
            ("eero inc.", "eero"),
            ("Ubiquiti Inc", "Ubiquiti"),
            ("LG ELECTRONICS", "LG Electronics"),
            ("ZTE CORPORATION", "ZTE"),
            ("Incom Ltd", "Incom"),
            ("Foo Incom", "Foo Incom"),
            ("AVM Audiovisuelles Marketing und Computersysteme GmbH", "AVM Audiovisuelles Marketing und Computersysteme"),
            ("Co.,Ltd X", "Co"),
            ("Foo,Inc", "Foo"),
            ("A.", "A"),
            ("ABCD", "ABCD"),
            ("ABCDE", "Abcde"),
            ("\u{c9}COLE \u{c9}LECTRONIQUE", "\u{c9}cole \u{c9}lectronique"),
            ("...", "..."),
            (",", ","),
            ("", ""),
        ] {
            assert_eq!(short(full), want, "{full}");
        }
    }
}
