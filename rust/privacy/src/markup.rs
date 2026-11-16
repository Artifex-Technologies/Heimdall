//! Reading XML, HTML and CSS from hostile files just far enough to find addresses: tags with their attributes, the text of
//! style elements, `url(...)` and `@import` in CSS. No tree is built (nothing nests, nothing recurses), entities are decoded
//! only in attribute values, and every loop moves forward, so any input ends in time linear in its length.

/// A start (or empty) tag: its name (as written, prefix included) and attributes, and where its content starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    /// Byte offset just after the tag's '>'.
    pub end: usize,
    /// `<x/>`.
    pub empty: bool,
}

impl Tag {
    /// The local name in lower case ("draw:image" -> "image").
    pub fn local(&self) -> String {
        self.name.rsplit(':').next().unwrap_or("").to_ascii_lowercase()
    }
    /// An attribute by its name (case-insensitive, prefix included).
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// An attribute by its local name ("xlink:href" and "href" both match "href").
    pub fn attr_local(&self, local: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k.rsplit(':').next().unwrap_or("").eq_ignore_ascii_case(local)).map(|(_, v)| v.as_str())
    }
}

fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() || needle.is_empty() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

/// Finds a needle ignoring ASCII case.
pub fn find_ci(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() || needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle)).map(|p| p + from)
}

/// Every start tag of a document, in order, at most `max` of them. Comments, CDATA sections, declarations and processing
/// instructions are skipped; so is the content of HTML's script and style elements and of XML's CDATA (callers that want a
/// style element's text take it from `end` with `text_until`).
pub fn tags(doc: &[u8], max: usize) -> Vec<Tag> {
    let mut out = vec![];
    let mut i = 0;
    while out.len() < max {
        let Some(lt) = doc[i.min(doc.len())..].iter().position(|&b| b == b'<').map(|p| p + i) else { break };
        let rest = &doc[lt..];
        if rest.starts_with(b"<!--") {
            i = find(doc, lt + 4, b"-->").map_or(doc.len(), |e| e + 3);
            continue;
        }
        if rest.starts_with(b"<![CDATA[") {
            i = find(doc, lt + 9, b"]]>").map_or(doc.len(), |e| e + 3);
            continue;
        }
        if rest.starts_with(b"<!") || rest.starts_with(b"<?") || rest.starts_with(b"</") {
            i = doc[lt + 1..].iter().position(|&b| b == b'>').map_or(doc.len(), |e| lt + 1 + e + 1);
            continue;
        }
        let (tag, next) = parse_tag(doc, lt + 1);
        i = next.max(lt + 1);
        if let Some(t) = tag {
            let raw_text = matches!(t.name.to_ascii_lowercase().as_str(), "script" | "style" | "textarea" | "title");
            let end = t.end;
            let name = t.name.clone();
            out.push(t);
            if raw_text {
                // skip to the matching end tag: HTML does not parse inside these
                let close = format!("</{name}");
                i = find_ci(doc, end, close.as_bytes()).unwrap_or(doc.len());
            }
        }
    }
    out
}

/// The text from `start` up to the next "</" (a style or script element's content).
pub fn text_until_close(doc: &[u8], start: usize) -> &[u8] {
    let s = start.min(doc.len());
    let e = find(doc, s, b"</").unwrap_or(doc.len());
    &doc[s..e]
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0C')
}

/// One tag from just after its '<': the tag (None when it is not one) and where scanning goes on.
fn parse_tag(doc: &[u8], mut i: usize) -> (Option<Tag>, usize) {
    let start = i;
    while i < doc.len() && !is_space(doc[i]) && doc[i] != b'>' && doc[i] != b'/' {
        i += 1;
    }
    let name = String::from_utf8_lossy(&doc[start..i]).into_owned();
    if name.is_empty() || !name.as_bytes()[0].is_ascii_alphabetic() {
        return (None, start);
    }
    let mut attrs = vec![];
    loop {
        while i < doc.len() && (is_space(doc[i]) || doc[i] == b'/') {
            i += 1;
        }
        if i >= doc.len() {
            return (Some(Tag { name, attrs, end: doc.len(), empty: false }), doc.len());
        }
        if doc[i] == b'>' {
            let empty = i > 0 && doc[i - 1] == b'/';
            return (Some(Tag { name, attrs, end: i + 1, empty }), i + 1);
        }
        let ks = i;
        while i < doc.len() && !is_space(doc[i]) && !matches!(doc[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let key = String::from_utf8_lossy(&doc[ks..i]).into_owned();
        while i < doc.len() && is_space(doc[i]) {
            i += 1;
        }
        let mut value = String::new();
        if i < doc.len() && doc[i] == b'=' {
            i += 1;
            while i < doc.len() && is_space(doc[i]) {
                i += 1;
            }
            if i < doc.len() && (doc[i] == b'"' || doc[i] == b'\'') {
                let q = doc[i];
                let vs = i + 1;
                let ve = doc[vs..].iter().position(|&b| b == q).map_or(doc.len(), |p| vs + p);
                value = decode_entities(&String::from_utf8_lossy(&doc[vs..ve]));
                i = (ve + 1).min(doc.len());
            } else {
                let vs = i;
                while i < doc.len() && !is_space(doc[i]) && doc[i] != b'>' {
                    i += 1;
                }
                value = decode_entities(&String::from_utf8_lossy(&doc[vs..i]));
            }
        }
        if !key.is_empty() && attrs.len() < 256 {
            attrs.push((key, value));
        }
        if ks == i {
            i += 1; // never stand still
        }
    }
}

/// The character entities of XML and the few named ones that matter for addresses.
pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let semi = rest.as_bytes()[..rest.len().min(12)].iter().position(|&b| b == b';');
        let decoded = semi.and_then(|e| {
            let ent = &rest[1..e];
            let c = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "colon" => Some(':'),
                "sol" => Some('/'),
                "Tab" => Some('\t'),
                "NewLine" => Some('\n'),
                "period" => Some('.'),
                _ => {
                    let n = if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                        u32::from_str_radix(h, 16).ok()
                    } else {
                        ent.strip_prefix('#').and_then(|d| d.parse::<u32>().ok())
                    };
                    n.and_then(char::from_u32)
                }
            };
            c.map(|c| (c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                rest = &rest[e + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// How an address is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addr {
    /// On this computer (a relative path, a local file, inline data, a fragment).
    Local,
    /// A server elsewhere (the web, a file share, any network scheme).
    Remote,
    /// Script code (`javascript:`).
    Script,
}

/// Where an address in a document points. Browsers drop tabs and line breaks inside addresses and ignore leading spaces, so
/// "ht&#9;tp://x" is read as "http://x" here too.
pub fn classify(raw: &str) -> Addr {
    let s: String = raw.chars().filter(|c| !matches!(c, '\t' | '\n' | '\r')).collect();
    let s = s.trim_matches(|c: char| c.is_whitespace() || c.is_control());
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("//") || lower.starts_with("\\\\") || lower.starts_with("/\\") || lower.starts_with("\\/") {
        return Addr::Remote;
    }
    let scheme_end = lower.find(':');
    let Some(se) = scheme_end else { return Addr::Local };
    let scheme = &lower[..se];
    let valid = !scheme.is_empty()
        && scheme.as_bytes()[0].is_ascii_alphabetic()
        && scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.');
    if !valid || scheme.len() == 1 {
        // no scheme, or a Windows drive letter ("C:\...")
        return Addr::Local;
    }
    match scheme {
        "javascript" | "vbscript" => Addr::Script,
        "data" | "about" | "blob" | "cid" | "mid" | "mailto" | "tel" | "sms" | "urn" => Addr::Local,
        "file" => {
            // file:///path and file://localhost/path are local; file://server/share is a network share
            let rest = &lower[se + 1..];
            match rest.strip_prefix("//") {
                Some(r) if !(r.starts_with('/') || r.starts_with("localhost/") || r.is_empty() || r == "localhost") => Addr::Remote,
                _ => Addr::Local,
            }
        }
        _ => Addr::Remote,
    }
}

/// Addresses in CSS text: `url(...)` and `@import "..."`.
pub fn css_urls(css: &[u8]) -> Vec<String> {
    let mut out = vec![];
    let mut i = 0;
    while let Some(p) = find_ci(css, i, b"url(") {
        let mut s = p + 4;
        while s < css.len() && is_space(css[s]) {
            s += 1;
        }
        let (vs, close) = match css.get(s) {
            Some(&q) if q == b'"' || q == b'\'' => (s + 1, q),
            _ => (s, b')'),
        };
        let ve = css[vs.min(css.len())..].iter().position(|&b| b == close).map_or(css.len(), |e| vs + e);
        out.push(String::from_utf8_lossy(&css[vs.min(ve)..ve]).trim().to_string());
        i = ve.max(p + 4);
        if out.len() >= 4096 {
            return out;
        }
    }
    let mut i = 0;
    while let Some(p) = find_ci(css, i, b"@import") {
        let mut s = p + 7;
        while s < css.len() && is_space(css[s]) {
            s += 1;
        }
        if let Some(&q) = css.get(s).filter(|&&q| q == b'"' || q == b'\'') {
            let ve = css[s + 1..].iter().position(|&b| b == q).map_or(css.len(), |e| s + 1 + e);
            out.push(String::from_utf8_lossy(&css[s + 1..ve]).to_string());
        }
        i = p + 7;
        if out.len() >= 4096 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_and_attributes() {
        let d = br#"<?xml version="1.0"?><!-- <img src="http://no"> --><svg xmlns:xlink="x"><image xlink:href='http://a/b.png' /><a href=x>t</a><script>var s="<img src=http://no2>"</script><p data-x=1></svg>"#;
        let t = tags(d, 100);
        let names: Vec<&str> = t.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["svg", "image", "a", "script", "p"]);
        assert_eq!(t[1].attr_local("href"), Some("http://a/b.png"));
        assert!(t[1].empty);
        assert_eq!(t[2].attr("HREF"), Some("x"));
        assert_eq!(t[4].attr("data-x"), Some("1"));
    }

    #[test]
    fn entities_cannot_hide_an_address() {
        assert_eq!(decode_entities("h&#116;tp&colon;//x&amp;y"), "http://x&y");
        assert_eq!(decode_entities("&#x68;ttp://"), "http://");
        assert_eq!(decode_entities("a & b &bogus; &#99999999;"), "a & b &bogus; &#99999999;");
        assert_eq!(classify("ht\ttp://x"), Addr::Remote);
        assert_eq!(classify(&decode_entities("ht&Tab;tp://x")), Addr::Remote);
    }

    #[test]
    fn addresses_are_classified() {
        for r in [
            "http://a",
            "HTTPS://a",
            "//cdn.example/x.js",
            "\\\\server\\share\\x",
            "ftp://x",
            "smb://nas/x",
            "file://server/share",
            "mms://x",
            "steam://run/1",
        ] {
            assert_eq!(classify(r), Addr::Remote, "{r}");
        }
        for l in
            ["img.png", "../a/b", "#frag", "data:image/png;base64,AA", "file:///home/x", "file://localhost/x", "C:\\x\\y", "mailto:a@b", ""]
        {
            assert_eq!(classify(l), Addr::Local, "{l}");
        }
        assert_eq!(classify(" javascript:alert(1)"), Addr::Script);
    }

    #[test]
    fn css_addresses() {
        let c = br#"@import "http://a/x.css"; .x { background: URL( 'http://b/y.png' ) } @font-face { src: url(fonts/z.woff) }"#;
        assert_eq!(css_urls(c), ["http://b/y.png", "fonts/z.woff", "http://a/x.css"]);
    }

    #[test]
    fn hostile_markup_ends() {
        for d in [
            &b"<"[..],
            b"<a",
            b"<a b='",
            b"<a b=\"x",
            b"<!--",
            b"<![CDATA[",
            b"<script>",
            b"<a\x00=1>",
            b"<<<<<>>>>",
            b"url(",
            b"url('",
            b"@import",
        ] {
            let _ = tags(d, 10);
            let _ = css_urls(d);
        }
        let many = b"<a x=1>".repeat(10_000);
        assert_eq!(tags(&many, 50).len(), 50);
    }
}
