//! Look-alike names: an app name, an app id or a file name that imitates another with letters from a different alphabet
//! ("Vivаldi" with a Cyrillic а), with letter-like symbols (fullwidth or mathematical letters, Roman numerals), or with
//! invisible and direction-changing characters (with U+202E in front, "fdp.exe" reads as "exe.pdf").
//!
//! This follows Unicode Technical Standard #39 (security mechanisms) in a small form: a script for each character (the blocks
//! that matter, not the whole Unicode script table), the "highly restrictive" rule for mixing scripts (one script, or Latin
//! with the Chinese, Japanese or Korean combinations), and a skeleton from a short table of the confusables that imitate
//! ASCII letters and digits (the Cyrillic, Greek, Armenian and Cherokee look-alikes, Latin's own deceptive letters,
//! fullwidth and mathematical letters, Roman numerals). A name that is ASCII is never flagged: the table only has to catch
//! what imitates ASCII.
//!
//! This file is the same in three repositories, so every place that shows a name decides the same way: Heimdall
//! (rust/privacy/src/lookalike.rs, the original), Labyrinth OS (packages/tools/src/lookalike.rs) and Yggdrasil
//! (packages/yggdrasil-ui/src/lookalike.rs). Change it in Heimdall first and copy it; the tests are part of the file.

/// The scripts this module tells apart. `Common` (digits, punctuation, symbols, spaces) and `Inherited` (combining marks)
/// go with any script.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Script {
    Common,
    Inherited,
    Latin,
    Greek,
    Cyrillic,
    Armenian,
    Hebrew,
    Arabic,
    Devanagari,
    Thai,
    Georgian,
    Cherokee,
    Hangul,
    Hiragana,
    Katakana,
    Bopomofo,
    Han,
    /// A letter of a script not listed here.
    Other,
}

impl Script {
    /// The script's name in plain words.
    pub fn name(self) -> &'static str {
        match self {
            Script::Common => "common",
            Script::Inherited => "combining",
            Script::Latin => "Latin",
            Script::Greek => "Greek",
            Script::Cyrillic => "Cyrillic",
            Script::Armenian => "Armenian",
            Script::Hebrew => "Hebrew",
            Script::Arabic => "Arabic",
            Script::Devanagari => "Devanagari",
            Script::Thai => "Thai",
            Script::Georgian => "Georgian",
            Script::Cherokee => "Cherokee",
            Script::Hangul => "Korean",
            Script::Hiragana => "Hiragana",
            Script::Katakana => "Katakana",
            Script::Bopomofo => "Bopomofo",
            Script::Han => "Chinese",
            Script::Other => "another alphabet's",
        }
    }
}

/// The script of a character (the blocks that matter; an unlisted letter is `Other`, anything else `Common`).
pub fn script(c: char) -> Script {
    let u = c as u32;
    match u {
        0x41..=0x5A | 0x61..=0x7A => Script::Latin,
        0x00..=0x7F => Script::Common,
        0xAA | 0xBA => Script::Latin,
        0x80..=0xBF | 0xD7 | 0xF7 => Script::Common,
        0xC0..=0x24F | 0x250..=0x2AF | 0x1D00..=0x1D25 | 0x1D2C..=0x1D5C | 0x1D62..=0x1D65 | 0x1D6B..=0x1D77 | 0x1D79..=0x1DBE => {
            Script::Latin
        }
        0x1E00..=0x1EFF | 0x2C60..=0x2C7F | 0xA722..=0xA7FF | 0xAB30..=0xAB5A | 0xAB5C..=0xAB64 | 0xFB00..=0xFB06 => Script::Latin,
        0xFF21..=0xFF3A | 0xFF41..=0xFF5A | 0x2160..=0x2188 | 0x212A | 0x212B | 0x2071 | 0x207F | 0x2090..=0x209C => Script::Latin,
        0x2B0..=0x2FF => Script::Common,
        0x300..=0x36F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F | 0x200C | 0x200D => Script::Inherited,
        0x370..=0x373 | 0x375..=0x377 | 0x37A..=0x37D | 0x37F | 0x384 | 0x386 | 0x388..=0x3E1 | 0x3F0..=0x3FF => Script::Greek,
        0x1D26..=0x1D2A | 0x1D5D..=0x1D61 | 0x1D66..=0x1D6A | 0x1DBF | 0x1F00..=0x1FFF | 0x2126 | 0xAB65 => Script::Greek,
        0x3E2..=0x3EF => Script::Other, // Coptic
        0x400..=0x52F | 0x1C80..=0x1C88 | 0x1D2B | 0x1D78 | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Script::Cyrillic,
        0x531..=0x58F | 0xFB13..=0xFB17 => Script::Armenian,
        0x591..=0x5FF | 0xFB1D..=0xFB4F => Script::Hebrew,
        0x600..=0x604 | 0x606..=0x60B | 0x60D..=0x61A | 0x61C..=0x61E | 0x620..=0x63F | 0x641..=0x64A | 0x656..=0x66F => Script::Arabic,
        0x671..=0x6DC | 0x6DE..=0x6FF | 0x750..=0x77F | 0x8A0..=0x8FF | 0xFB50..=0xFDFF | 0xFE70..=0xFEFC => Script::Arabic,
        0x900..=0x950 | 0x955..=0x963 | 0x966..=0x97F | 0xA8E0..=0xA8FF => Script::Devanagari,
        0xE01..=0xE3A | 0xE40..=0xE5B => Script::Thai,
        0x10A0..=0x10FA | 0x10FC..=0x10FF | 0x1C90..=0x1CBF | 0x2D00..=0x2D2D => Script::Georgian,
        0x13A0..=0x13FD | 0xAB70..=0xABBF => Script::Cherokee,
        0x1100..=0x11FF | 0x3131..=0x318E | 0xA960..=0xA97F | 0xAC00..=0xD7FB | 0xFFA0..=0xFFDC => Script::Hangul,
        0x3041..=0x3096 | 0x309D..=0x309F => Script::Hiragana,
        0x30A1..=0x30FA | 0x30FD..=0x30FF | 0x31F0..=0x31FF | 0x32D0..=0x32FE | 0xFF66..=0xFF6F | 0xFF71..=0xFF9D => Script::Katakana,
        0x3105..=0x312F | 0x31A0..=0x31BF => Script::Bopomofo,
        0x2E80..=0x2FD5 | 0x3005 | 0x3007 | 0x3021..=0x3029 | 0x3038..=0x303B | 0x3400..=0x4DBF | 0x4E00..=0x9FFF => Script::Han,
        0xF900..=0xFAD9 | 0x20000..=0x323AF => Script::Han,
        0xE0100..=0xE01EF | 0xFE00..=0xFE0F => Script::Inherited,
        // letter-like and mathematical symbols: no script of their own (they imitate Latin letters: the table catches that)
        0x2100..=0x214F | 0x1D400..=0x1D7FF => Script::Common,
        _ if c.is_alphabetic() => Script::Other,
        _ => Script::Common,
    }
}

/// Invisible characters: zero-width spaces and joiners, word joiners, invisible operators, the byte order mark, the soft
/// hyphen, fillers and tags. A name needs none of them to be read, and each can make two different names look the same.
/// (The zero-width joiner inside an emoji sequence is the one ordinary use; names of apps and files do not need it.)
pub fn invisible(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x34F | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F | 0x200B..=0x200D | 0x2060..=0x2064 | 0x206A..=0x206F
        | 0x3164 | 0xFEFF | 0xFFA0 | 0x1BCA0..=0x1BCA3 | 0xE0000..=0xE007F)
}

/// Characters that change the direction of the text around them: with one, "fdp.exe" can read as "exe.pdf".
pub fn direction_control(c: char) -> bool {
    matches!(c as u32, 0x61C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

/// Control characters (C0, DEL, C1) and line or paragraph separators: never part of a name.
fn control(c: char) -> bool {
    c.is_control() || matches!(c as u32, 0x2028 | 0x2029)
}

/// The ASCII that a confusable character imitates (Unicode's confusables, the part that imitates ASCII), or None.
pub fn imitates(c: char) -> Option<&'static str> {
    let u = c as u32;
    // fullwidth ASCII
    if (0xFF01..=0xFF5E).contains(&u) {
        return Some(ASCII[(u - 0xFF01 + 1) as usize]);
    }
    // mathematical alphanumeric letters: 13 styles of A-Z a-z from U+1D400, then the digits in 5 styles from U+1D7CE
    if (0x1D400..=0x1D6A3).contains(&u) {
        let i = ((u - 0x1D400) % 52) as usize;
        return Some(LETTERS[i]);
    }
    if (0x1D7CE..=0x1D7FF).contains(&u) {
        return Some(DIGITS[((u - 0x1D7CE) % 10) as usize]);
    }
    // the letters in a circle or brackets imitate nothing well enough to matter; the table has the rest
    TABLE.binary_search_by_key(&u, |&(k, _)| k).ok().map(|i| TABLE[i].1)
}

const LETTERS: [&str; 52] = [
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a",
    "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
];
const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
// index 1..=94: the printable ASCII from "!" (index 0 is unused)
const ASCII: [&str; 95] = [
    "", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":",
    ";", "<", "=", ">", "?", "@", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U",
    "V", "W", "X", "Y", "Z", "[", "\\", "]", "^", "_", "`", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p",
    "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "{", "|", "}", "~",
];

/// Single characters that imitate ASCII, sorted by code point (from Unicode's confusables.txt).
const TABLE: &[(u32, &str)] = &[
    (0x00D7, "x"),
    (0x0131, "i"),
    (0x017F, "f"),
    (0x01C0, "l"),
    (0x01C3, "!"),
    (0x0237, "j"),
    (0x0251, "a"),
    (0x0261, "g"),
    (0x0269, "i"),
    (0x026A, "i"),
    (0x0282, "s"),
    (0x028F, "y"),
    (0x0299, "B"),
    (0x029C, "H"),
    (0x02BC, "'"),
    (0x0391, "A"),
    (0x0392, "B"),
    (0x0395, "E"),
    (0x0396, "Z"),
    (0x0397, "H"),
    (0x0399, "I"),
    (0x039A, "K"),
    (0x039C, "M"),
    (0x039D, "N"),
    (0x039F, "O"),
    (0x03A1, "P"),
    (0x03A4, "T"),
    (0x03A5, "Y"),
    (0x03A7, "X"),
    (0x03B1, "a"),
    (0x03B3, "y"),
    (0x03B9, "i"),
    (0x03BD, "v"),
    (0x03BF, "o"),
    (0x03C1, "p"),
    (0x03C3, "o"),
    (0x03C5, "u"),
    (0x03F2, "c"),
    (0x03F3, "j"),
    (0x03F9, "C"),
    (0x03FA, "M"),
    (0x0405, "S"),
    (0x0406, "I"),
    (0x0408, "J"),
    (0x0410, "A"),
    (0x0412, "B"),
    (0x0415, "E"),
    (0x0417, "3"),
    (0x041A, "K"),
    (0x041C, "M"),
    (0x041D, "H"),
    (0x041E, "O"),
    (0x0420, "P"),
    (0x0421, "C"),
    (0x0422, "T"),
    (0x0423, "Y"),
    (0x0425, "X"),
    (0x042C, "b"),
    (0x0430, "a"),
    (0x0431, "6"),
    (0x0435, "e"),
    (0x043E, "o"),
    (0x0440, "p"),
    (0x0441, "c"),
    (0x0443, "y"),
    (0x0445, "x"),
    (0x0455, "s"),
    (0x0456, "i"),
    (0x0458, "j"),
    (0x04AE, "Y"),
    (0x04AF, "y"),
    (0x04BA, "h"),
    (0x04BB, "h"),
    (0x04C0, "I"),
    (0x04CF, "l"),
    (0x0501, "d"),
    (0x051A, "Q"),
    (0x051B, "q"),
    (0x051C, "W"),
    (0x051D, "w"),
    (0x0555, "O"),
    (0x0561, "w"),
    (0x0563, "q"),
    (0x0566, "q"),
    (0x0570, "h"),
    (0x0578, "n"),
    (0x057C, "n"),
    (0x057D, "u"),
    (0x0581, "g"),
    (0x0585, "o"),
    (0x05C0, "l"),
    (0x05D5, "l"),
    (0x05DF, "l"),
    (0x0627, "l"),
    (0x0660, "."),
    (0x0661, "l"),
    (0x0665, "o"),
    (0x06F1, "l"),
    (0x06F5, "o"),
    (0x13A2, "T"),
    (0x13AA, "A"),
    (0x13AB, "J"),
    (0x13AC, "E"),
    (0x13B3, "W"),
    (0x13B7, "M"),
    (0x13BB, "H"),
    (0x13C0, "G"),
    (0x13C3, "Z"),
    (0x13D9, "V"),
    (0x13DA, "S"),
    (0x13DE, "L"),
    (0x13DF, "C"),
    (0x13E2, "P"),
    (0x13E6, "K"),
    (0x13F4, "B"),
    (0x1D00, "A"),
    (0x1D04, "c"),
    (0x1D05, "D"),
    (0x1D07, "E"),
    (0x1D0A, "J"),
    (0x1D0B, "K"),
    (0x1D0D, "M"),
    (0x1D0F, "o"),
    (0x1D11, "o"),
    (0x1D18, "P"),
    (0x1D1B, "T"),
    (0x1D1C, "u"),
    (0x1D20, "v"),
    (0x1D21, "w"),
    (0x1D22, "z"),
    (0x2010, "-"),
    (0x2011, "-"),
    (0x2012, "-"),
    (0x2013, "-"),
    (0x2018, "'"),
    (0x2019, "'"),
    (0x201A, ","),
    (0x2024, "."),
    (0x2044, "/"),
    (0x2102, "C"),
    (0x210A, "g"),
    (0x210B, "H"),
    (0x210C, "H"),
    (0x210D, "H"),
    (0x210E, "h"),
    (0x2110, "I"),
    (0x2111, "I"),
    (0x2112, "L"),
    (0x2113, "l"),
    (0x2115, "N"),
    (0x2119, "P"),
    (0x211A, "Q"),
    (0x211B, "R"),
    (0x211C, "R"),
    (0x211D, "R"),
    (0x2124, "Z"),
    (0x2128, "Z"),
    (0x212A, "K"),
    (0x212C, "B"),
    (0x212D, "C"),
    (0x212E, "e"),
    (0x212F, "e"),
    (0x2130, "E"),
    (0x2131, "F"),
    (0x2133, "M"),
    (0x2134, "o"),
    (0x2139, "i"),
    (0x2145, "D"),
    (0x2146, "d"),
    (0x2147, "e"),
    (0x2148, "i"),
    (0x2149, "j"),
    (0x2160, "I"),
    (0x2164, "V"),
    (0x2169, "X"),
    (0x216C, "L"),
    (0x216D, "C"),
    (0x216E, "D"),
    (0x216F, "M"),
    (0x2170, "i"),
    (0x2174, "v"),
    (0x2179, "x"),
    (0x217C, "l"),
    (0x217D, "c"),
    (0x217E, "d"),
    (0x217F, "m"),
    (0x2215, "/"),
    (0x2223, "l"),
    (0x2228, "v"),
    (0x222A, "U"),
    (0x22C1, "v"),
    (0x2373, "i"),
    (0x2374, "p"),
    (0x2379, "w"),
    (0x237A, "a"),
    (0x2A2F, "x"),
    (0x2C9E, "O"),
    (0x2C9F, "o"),
    (0x3007, "O"),
    (0xA731, "s"),
    (0xA76A, "3"),
    (0xA7AE, "l"),
    (0xAB83, "w"),
    (0xFE31, "l"),
    (0xFE32, "l"),
    (0xFE58, "-"),
];

/// The name as the ASCII it imitates: each confusable character replaced by its ASCII, everything else kept (invisible and
/// direction-changing characters are dropped, as they are not seen).
pub fn as_seen(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if invisible(c) || direction_control(c) {
            continue;
        }
        match imitates(c) {
            Some(a) => out.push_str(a),
            None => out.push(c),
        }
    }
    out
}

/// A skeleton in the sense of TR39: two names with the same skeleton look the same. The ASCII the characters imitate, then
/// the ASCII look-alikes folded (0 and O, 1 l I and |, "rn" and m, "vv" and w), in lower case.
pub fn skeleton(s: &str) -> String {
    let mut a: String = as_seen(s)
        .chars()
        .map(|c| match c {
            '0' => 'O',
            '1' | 'I' | '|' => 'l',
            c => c,
        })
        .collect::<String>()
        .to_lowercase();
    for (from, to) in [("rn", "m"), ("vv", "w"), ("cl", "d")] {
        a = a.replace(from, to);
    }
    a
}

/// Two names that look the same (and are not the same).
pub fn confusable(a: &str, b: &str) -> bool {
    a != b && skeleton(a) == skeleton(b)
}

/// Why a name was flagged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Letters of more than one alphabet (beyond the Chinese, Japanese and Korean combinations).
    MixedScripts(Vec<Script>),
    /// Letters or symbols that imitate ASCII ones; the name as it reads.
    LooksLike(String),
    /// Characters that are not seen.
    Invisible,
    /// Characters that turn the direction of the text.
    Direction,
    /// Control characters or line breaks.
    Control,
}

/// What `check` found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub reasons: Vec<Reason>,
}

impl Report {
    /// The name may be imitating another: show a warning and what it really is.
    pub fn suspicious(&self) -> bool {
        !self.reasons.is_empty()
    }

    /// The name it imitates, when it imitates an ASCII one.
    pub fn looks_like(&self) -> Option<&str> {
        self.reasons.iter().find_map(|r| match r {
            Reason::LooksLike(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// The reasons in plain words, one sentence ("" when there are none).
    pub fn words(&self) -> String {
        let mut parts: Vec<String> = vec![];
        for r in &self.reasons {
            parts.push(match r {
                Reason::MixedScripts(s) => {
                    let names: Vec<&str> = s.iter().map(|x| x.name()).collect();
                    format!("it mixes {} letters", join_and(&names))
                }
                Reason::LooksLike(a) => format!("it has letters that only look like \"{a}\""),
                Reason::Invisible => "it has invisible characters".into(),
                Reason::Direction => "it has characters that reverse the text, so it may read differently from what it is".into(),
                Reason::Control => "it has control characters".into(),
            });
        }
        if parts.is_empty() {
            return String::new();
        }
        let mut s = join_and(&parts.iter().map(String::as_str).collect::<Vec<_>>());
        if let Some(f) = s.get_mut(0..1) {
            f.make_ascii_uppercase();
        }
        s.push('.');
        s
    }
}

fn join_and(v: &[&str]) -> String {
    match v {
        [] => String::new(),
        [a] => a.to_string(),
        [a @ .., z] => format!("{} and {z}", a.join(", ")),
    }
}

/// The scripts of a name's letters (no Common, no Inherited), in order of first appearance.
pub fn scripts(s: &str) -> Vec<Script> {
    let mut v = vec![];
    for c in s.chars() {
        let k = script(c);
        if !matches!(k, Script::Common | Script::Inherited) && !v.contains(&k) {
            v.push(k);
        }
    }
    v
}

/// The "highly restrictive" rule of TR39: one script, or Latin with Han and the Japanese kana, with Han and Bopomofo, or
/// with Han and Hangul (each part optional).
fn allowed_mix(v: &[Script]) -> bool {
    use Script::*;
    if v.len() <= 1 {
        return true;
    }
    let within = |set: &[Script]| v.iter().all(|s| set.contains(s));
    within(&[Latin, Han, Hiragana, Katakana]) || within(&[Latin, Han, Bopomofo]) || within(&[Latin, Han, Hangul])
}

/// Checks a name (an app's name or id, a file name). A plain ASCII name without control characters is always fine.
pub fn check(name: &str) -> Report {
    let mut r = Report::default();
    if name.bytes().all(|b| (0x20..0x7F).contains(&b)) {
        return r;
    }
    if name.chars().any(control) {
        r.reasons.push(Reason::Control);
    }
    if name.chars().any(direction_control) {
        r.reasons.push(Reason::Direction);
    }
    if name.chars().any(invisible) {
        r.reasons.push(Reason::Invisible);
    }
    let sc = scripts(name);
    if !allowed_mix(&sc) {
        r.reasons.push(Reason::MixedScripts(sc));
    }
    // a non-ASCII character that imitates ASCII, in a name that then reads as ASCII where it has letters
    let seen = as_seen(name);
    let imitating = name.chars().any(|c| !c.is_ascii() && imitates(c).is_some());
    let letters_ascii = seen.chars().filter(|c| c.is_alphanumeric()).all(|c| c.is_ascii());
    if imitating && letters_ascii && seen.chars().any(|c| c.is_ascii_alphanumeric()) {
        r.reasons.push(Reason::LooksLike(seen.chars().filter(|c| !c.is_control()).collect()));
    }
    r
}

/// The name made safe to show beside a warning: control, invisible and direction-changing characters written as
/// "<U+202E>", so nothing hides and nothing turns the text around.
pub fn visible(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if control(c) || invisible(c) || direction_control(c) {
            out.push_str(&format!("<U+{:04X}>", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_names_are_fine() {
        for n in ["Vivaldi", "org.mozilla.firefox", "LibreOffice Writer", "report (final).pdf", "x", ""] {
            assert!(!check(n).suspicious(), "{n}");
        }
    }

    #[test]
    fn a_cyrillic_a_in_vivaldi_is_caught() {
        let r = check("Viv\u{0430}ldi");
        assert!(r.suspicious());
        assert_eq!(r.looks_like(), Some("Vivaldi"));
        assert!(r.reasons.contains(&Reason::MixedScripts(vec![Script::Latin, Script::Cyrillic])));
        assert_eq!(r.words(), "It mixes Latin and Cyrillic letters and it has letters that only look like \"Vivaldi\".");
        assert!(confusable("Viv\u{0430}ldi", "Vivaldi"));
        assert!(!confusable("Vivaldi", "Vivaldi"), "the same name is not a look-alike of itself");
    }

    #[test]
    fn whole_script_imitations_are_caught() {
        // all Cyrillic, reads as "Space"; all Greek, reads as "TOKEN"
        let r = check("\u{0405}\u{0440}\u{0430}\u{0441}\u{0435}");
        assert_eq!(r.looks_like(), Some("Space"));
        assert!(!r.reasons.iter().any(|x| matches!(x, Reason::MixedScripts(_))), "one script, yet it imitates");
        assert_eq!(check("\u{03A4}\u{039F}\u{039A}\u{0395}\u{039D}").looks_like(), Some("TOKEN"));
        // Cherokee, Armenian
        assert_eq!(check("\u{13DA}\u{13A2}\u{13AC}\u{13AA}\u{13B7}").looks_like(), Some("STEAM"));
        assert_eq!(check("g\u{0585}\u{0585}gle").looks_like(), Some("google"));
    }

    #[test]
    fn letter_like_symbols_are_caught() {
        assert_eq!(check("\u{FF36}\u{FF49}\u{FF56}\u{FF41}\u{FF4C}\u{FF44}\u{FF49}").looks_like(), Some("Vivaldi"), "fullwidth");
        assert_eq!(check("\u{1D405}\u{1D422}\u{1D42B}\u{1D41E}").looks_like(), Some("Fire"), "mathematical bold");
        assert_eq!(check("Stea\u{217F}").looks_like(), Some("Steam"), "a Roman numeral");
        assert_eq!(check("V\u{0131}valdi").looks_like(), Some("Vivaldi"), "a dotless i");
        assert_eq!(check("\u{212A}eePass").looks_like(), Some("KeePass"), "the Kelvin sign");
        assert_eq!(check("ver\u{1D7E3}.pdf").looks_like(), Some("ver1.pdf"), "a mathematical digit");
    }

    #[test]
    fn hidden_and_turning_characters_are_caught() {
        let r = check("invoice\u{202E}fdp.exe");
        assert!(r.reasons.contains(&Reason::Direction));
        assert_eq!(visible("invoice\u{202E}fdp.exe"), "invoice<U+202E>fdp.exe");
        assert!(check("Fire\u{200B}fox").reasons.contains(&Reason::Invisible));
        assert_eq!(check("Fire\u{200B}fox").looks_like(), None, "nothing imitates: only the hidden character");
        assert!(check("a\nb").reasons.contains(&Reason::Control));
        assert_eq!(visible("a\u{0007}b\u{FEFF}"), "a<U+0007>b<U+FEFF>");
        assert!(!check("a\nb").reasons.contains(&Reason::Invisible));
    }

    #[test]
    fn real_names_in_other_alphabets_are_fine() {
        for n in [
            "Café",
            "Señal",
            "Gräfin",
            "Блокнот",                 // Russian "notepad": one script, does not read as ASCII
            "Ελληνικά",                // Greek
            "メモ帳",                  // Japanese: Katakana and Han
            "LINE ライン",             // Latin with Katakana is allowed
            "카카오톡",                // Korean
            "微信 WeChat",             // Chinese with Latin
            "עברית",                   // Hebrew
            "العربية",                 // Arabic
            "µTorrent",                // the micro sign is a symbol, not Greek
            "naïve résumé (copy).odt", // accents are their own letters
        ] {
            assert!(!check(n).suspicious(), "{n}: {:?}", check(n));
        }
    }

    #[test]
    fn mixing_alphabets_is_flagged_even_without_imitation() {
        let r = check("Teст");
        assert!(r.reasons.contains(&Reason::MixedScripts(vec![Script::Latin, Script::Cyrillic])));
        let r = check("Γράφω Writer");
        assert!(r.reasons.contains(&Reason::MixedScripts(vec![Script::Greek, Script::Latin])));
        assert!(check("한글 カタカナ").suspicious(), "Korean with Japanese kana is not one of the allowed mixes");
    }

    #[test]
    fn skeletons_fold_ascii_look_alikes_too() {
        assert_eq!(skeleton("PayPa1"), skeleton("PayPal"));
        assert_eq!(skeleton("rnozilla"), skeleton("mozilla"));
        assert!(confusable("G0OGLE", "GOOGLE"));
        assert!(!confusable("Vivaldi", "Vivaldl"), "i and l are different letters");
    }

    #[test]
    fn the_table_is_sorted_and_points_at_ascii() {
        assert!(TABLE.windows(2).all(|w| w[0].0 < w[1].0), "binary search needs the table sorted");
        for (k, v) in TABLE {
            assert!(v.is_ascii() && !v.is_empty(), "{k:X}");
            assert!(char::from_u32(*k).is_some_and(|c| !c.is_ascii()), "{k:X}");
        }
        assert_eq!(imitates('\u{FF01}'), Some("!"));
        assert_eq!(imitates('\u{FF5E}'), Some("~"));
        assert_eq!(imitates('\u{1D6A3}'), Some("z"));
        assert_eq!(imitates('\u{1D7FF}'), Some("9"));
        assert_eq!(imitates('a'), None);
    }

    #[test]
    fn any_text_is_checked_without_panicking() {
        // every character in the planes that have any, one at a time and beside ASCII
        for u in (0..0x3_0000u32).chain(0xE_0000..0xE_0200) {
            if let Some(c) = char::from_u32(u) {
                let s = format!("a{c}b");
                let r = check(&s);
                let _ = (r.words(), visible(&s), skeleton(&s));
            }
        }
    }
}
