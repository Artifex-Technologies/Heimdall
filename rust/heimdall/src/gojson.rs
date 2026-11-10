//! JSON read and written the way Go's encoding/json does, for every file that comes from outside (Sarina's sessions,
//! Limbo's events, the config) and for the alerts Heimdall writes.
//!
//! Why not serde_json for these: Go is lenient where a strict reader would let an attacker hide. A string with a lone UTF-16
//! surrogate (`"\ud800"`) or a stray byte that is not UTF-8 is read by Go with U+FFFD in its place; serde_json refuses the
//! whole document, so a session file planted with one such escape would never be inspected at all. Go also matches an
//! object's keys to a struct's fields without regard to case, keeps the last of duplicate keys, and ignores unknown ones.
//! This reader does all of that, and the writer escapes as Go does (`<`, `>`, `&`, U+2028 and U+2029 as `\u` escapes), so
//! the alert log reads the same byte for byte. The fuzz target `json` checks it against serde_json on valid documents.

use crate::gotext;
use std::fmt;

/// A JSON value. Numbers keep their text, so each reader can apply Go's rule for its own type (an int refuses "1.0").
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// Members in document order, duplicates kept (a struct reader applies them in order, so the last one wins).
    Object(Vec<(String, Value)>),
}

/// Why a document did not read.
#[derive(Clone, Debug, PartialEq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

/// Go's nesting limit (encoding/json's scanner refuses deeper documents).
const MAX_DEPTH: usize = 10_000;

/// Reads one JSON document (surrounding white space allowed, nothing else after it), as Go's `json.Unmarshal` does.
pub fn parse(b: &[u8]) -> Result<Value, Error> {
    let mut p = Parser { b, i: 0, depth: 0 };
    p.ws();
    // a document cut short is Go's "unexpected end of JSON input", whatever was being read
    let v = p.value().map_err(|e| if p.i >= b.len() { Error("unexpected end of JSON input".into()) } else { e })?;
    p.ws();
    if p.i != b.len() {
        return err(format!("invalid character {} after top-level value", p.describe()));
    }
    Ok(v)
}

/// Reads the first JSON value of `b` and ignores what follows, as Go's `json.Decoder.Decode` does for one value.
pub fn parse_first(b: &[u8]) -> Result<Value, Error> {
    let mut p = Parser { b, i: 0, depth: 0 };
    p.ws();
    // the decoder reads a stream: one cut short is Go's io.ErrUnexpectedEOF (an empty one io.EOF)
    p.value().map_err(|e| match p.i >= b.len() {
        true if b.iter().all(u8::is_ascii_whitespace) => Error("EOF".into()),
        true => Error("unexpected EOF".into()),
        false => e,
    })
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn describe(&self) -> String {
        match self.b.get(self.i) {
            None => "end of input".into(),
            Some(&c) if c.is_ascii_graphic() => format!("'{}'", c as char),
            Some(&c) => format!("byte 0x{c:02x}"),
        }
    }

    fn value(&mut self) -> Result<Value, Error> {
        match self.b.get(self.i) {
            None => err("unexpected end of JSON input"),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.word("true", Value::Bool(true)),
            Some(b'f') => self.word("false", Value::Bool(false)),
            Some(b'n') => self.word("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => err(format!("invalid character {} looking for beginning of value", self.describe())),
        }
    }

    fn word(&mut self, w: &str, v: Value) -> Result<Value, Error> {
        if self.b[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Ok(v)
        } else {
            err(format!("invalid literal near offset {}", self.i))
        }
    }

    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return err("exceeded max depth");
        }
        Ok(())
    }

    fn object(&mut self) -> Result<Value, Error> {
        self.enter()?;
        self.i += 1;
        let mut members = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.ws();
            if self.b.get(self.i) != Some(&b'"') {
                return err(format!("invalid character {} looking for beginning of object key string", self.describe()));
            }
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return err(format!("invalid character {} after object key", self.describe()));
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            members.push((k, v));
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Object(members));
                }
                _ => return err(format!("invalid character {} after object key:value pair", self.describe())),
            }
        }
    }

    fn array(&mut self) -> Result<Value, Error> {
        self.enter()?;
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(items));
                }
                _ => return err(format!("invalid character {} after array element", self.describe())),
            }
        }
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.i;
        let b = self.b;
        let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
        if b[self.i] == b'-' {
            self.i += 1;
        }
        match b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while digit(self.i) {
                    self.i += 1;
                }
            }
            _ => return err(format!("invalid character {} in numeric literal", self.describe())),
        }
        if b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !digit(self.i) {
                return err(format!("invalid character {} after decimal point in numeric literal", self.describe()));
            }
            while digit(self.i) {
                self.i += 1;
            }
        }
        if matches!(b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !digit(self.i) {
                return err(format!("invalid character {} in exponent of numeric literal", self.describe()));
            }
            while digit(self.i) {
                self.i += 1;
            }
        }
        // ASCII by construction
        Ok(Value::Number(String::from_utf8_lossy(&b[start..self.i]).into_owned()))
    }

    /// Four hex digits after `\u` at `at`, as Go's getu4 (-1: not an escape).
    fn u4(&self, at: usize) -> Option<u32> {
        let h = self.b.get(at..at + 6)?;
        if h[0] != b'\\' || h[1] != b'u' {
            return None;
        }
        let mut v = 0u32;
        for &c in &h[2..] {
            v = v * 16 + (c as char).to_digit(16)?;
        }
        Some(v)
    }

    fn string(&mut self) -> Result<String, Error> {
        self.i += 1; // the opening quote
        let b = self.b;
        let mut out: Vec<u8> = Vec::new();
        loop {
            // copy the plain run in one go
            let run = self.i;
            while let Some(&c) = b.get(self.i) {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            out.extend_from_slice(&b[run..self.i]);
            match b.get(self.i) {
                None => return err("unexpected end of JSON input"),
                Some(b'"') => {
                    self.i += 1;
                    // stray bytes become U+FFFD one by one, as Go's decoder writes them
                    return Ok(gotext::lossy_owned(out));
                }
                Some(&c) if c < 0x20 => return err(format!("invalid character byte 0x{c:02x} in string literal")),
                Some(_) => {
                    // a backslash
                    let esc = match b.get(self.i + 1) {
                        None => return err("unexpected end of JSON input"),
                        Some(&e) => e,
                    };
                    let simple = match esc {
                        b'"' => Some(b'"'),
                        b'\\' => Some(b'\\'),
                        b'/' => Some(b'/'),
                        b'b' => Some(8),
                        b'f' => Some(12),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'u' => None,
                        _ => return err(format!("invalid character '{}' in string escape code", esc as char)),
                    };
                    if let Some(c) = simple {
                        out.push(c);
                        self.i += 2;
                        continue;
                    }
                    let Some(r) = self.u4(self.i) else {
                        return err("invalid character in \\u hexadecimal character escape");
                    };
                    self.i += 6;
                    let mut ch = char::from_u32(r);
                    if (0xD800..0xE000).contains(&r) {
                        // a pair only when a high surrogate is followed by a low one; anything else is U+FFFD (Go)
                        ch = None;
                        if r < 0xDC00 {
                            if let Some(r2) = self.u4(self.i) {
                                if (0xDC00..0xE000).contains(&r2) {
                                    ch = char::from_u32(0x10000 + ((r - 0xD800) << 10) + (r2 - 0xDC00));
                                    self.i += 6;
                                }
                            }
                        }
                    }
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.unwrap_or('\u{FFFD}').encode_utf8(&mut buf).as_bytes());
                }
            }
        }
    }
}

// ---- reading a value into Go-typed fields ----

/// Go's field-name match for keys of a struct: the key equals the field name, ignoring case (ASCII letters, plus the long s
/// and the Kelvin sign, which Go folds to s and k).
pub fn key_matches(key: &str, field: &str) -> bool {
    if key == field {
        return true;
    }
    let mut k = key.chars().map(|c| match c {
        '\u{17F}' => 's',
        '\u{212A}' => 'k',
        c => c.to_ascii_lowercase(),
    });
    let mut f = field.chars();
    loop {
        match (k.next(), f.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a == b.to_ascii_lowercase() => {}
            _ => return false,
        }
    }
}

/// An object's members for a struct of the given field names: (field index, value) in document order, each member matched as
/// Go matches it (an exact name first, else a case-insensitive one). `None` for null (Go leaves the struct as it is).
pub fn struct_members<'v>(v: &'v Value, fields: &[&str], what: &str) -> Result<Option<Vec<(usize, &'v Value)>>, Error> {
    let members = match v {
        Value::Null => return Ok(None),
        Value::Object(m) => m,
        other => return err(format!("json: cannot unmarshal {} into Go value of type {what}", kind(other))),
    };
    let mut out = Vec::new();
    for (k, val) in members {
        let idx = fields.iter().position(|f| f == k).or_else(|| fields.iter().position(|f| key_matches(k, f)));
        if let Some(i) = idx {
            out.push((i, val));
        }
    }
    Ok(Some(out))
}

pub fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn mismatch<T>(v: &Value, ty: &str, field: &str) -> Result<T, Error> {
    let what = match v {
        Value::Number(n) => format!("number {n}"),
        other => kind(other).to_string(),
    };
    err(format!("json: cannot unmarshal {what} into Go struct field {field} of type {ty}"))
}

/// A Go-typed target: how one JSON value is read into it. Null leaves the target as it was (Go), except for slices and maps,
/// which Go sets to nil.
pub trait FromGo: Sized {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error>;
}

impl FromGo for String {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error> {
        match v {
            Value::Null => Ok(()),
            Value::String(s) => {
                *self = s.clone();
                Ok(())
            }
            other => mismatch(other, "string", field),
        }
    }
}

impl FromGo for bool {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error> {
        match v {
            Value::Null => Ok(()),
            Value::Bool(b) => {
                *self = *b;
                Ok(())
            }
            other => mismatch(other, "bool", field),
        }
    }
}

macro_rules! go_int {
    ($t:ty, $name:expr) => {
        impl FromGo for $t {
            fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error> {
                match v {
                    Value::Null => Ok(()),
                    Value::Number(n) => match n.parse::<$t>() {
                        Ok(x) => {
                            *self = x;
                            Ok(())
                        }
                        Err(_) => mismatch(v, $name, field),
                    },
                    other => mismatch(other, $name, field),
                }
            }
        }
    };
}
go_int!(i64, "int");
go_int!(i32, "int32");
go_int!(u64, "uint64");
go_int!(u32, "uint32");

impl FromGo for f64 {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error> {
        match v {
            Value::Null => Ok(()),
            Value::Number(n) => match n.parse::<f64>() {
                Ok(x) if x.is_finite() => {
                    *self = x;
                    Ok(())
                }
                _ => mismatch(v, "float64", field),
            },
            other => mismatch(other, "float64", field),
        }
    }
}

impl<T: FromGo + Default> FromGo for Vec<T> {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error> {
        match v {
            Value::Null => {
                self.clear();
                Ok(())
            }
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                let mut first: Option<Error> = None;
                for it in items {
                    let mut x = T::default();
                    if let Err(e) = x.read_into(it, field) {
                        first.get_or_insert(e);
                    }
                    out.push(x);
                }
                *self = out;
                first.map_or(Ok(()), Err)
            }
            other => mismatch(other, "slice", field),
        }
    }
}

impl<T: FromGo + Default> FromGo for std::collections::BTreeMap<String, T> {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error> {
        match v {
            Value::Null => {
                self.clear();
                Ok(())
            }
            Value::Object(members) => {
                // Go keeps an existing map and adds to it
                let mut first: Option<Error> = None;
                for (k, it) in members {
                    let mut x = T::default();
                    if let Err(e) = x.read_into(it, field) {
                        first.get_or_insert(e);
                        continue;
                    }
                    self.insert(k.clone(), x);
                }
                first.map_or(Ok(()), Err)
            }
            other => mismatch(other, "map", field),
        }
    }
}

impl FromGo for crate::gotime::Time {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), Error> {
        match v {
            Value::Null => Ok(()),
            Value::String(s) => match crate::gotime::Time::parse_rfc3339(s) {
                Some(t) => {
                    *self = t;
                    Ok(())
                }
                None => err(format!("parsing time {} as RFC 3339: cannot parse (field {field})", gotext::quote(s))),
            },
            other => mismatch(other, "time.Time", field),
        }
    }
}

impl FromGo for Value {
    fn read_into(&mut self, v: &Value, _field: &str) -> Result<(), Error> {
        *self = v.clone();
        Ok(())
    }
}

/// Declares how a struct reads from JSON the way Go's `json.Unmarshal` would: each listed field by its JSON name. Every
/// member is applied in document order and the first type error is returned after all of them were tried, as in Go.
#[macro_export]
macro_rules! go_struct {
    ($ty:ty { $($field:ident : $name:literal),* $(,)? }) => {
        impl $crate::gojson::FromGo for $ty {
            fn read_into(&mut self, v: &$crate::gojson::Value, _field: &str) -> Result<(), $crate::gojson::Error> {
                const NAMES: &[&str] = &[$($name),*];
                let Some(members) = $crate::gojson::struct_members(v, NAMES, stringify!($ty))? else { return Ok(()) };
                let mut first: Option<$crate::gojson::Error> = None;
                for (i, val) in members {
                    let mut k = 0usize;
                    $(
                        if i == k {
                            if let Err(e) = $crate::gojson::FromGo::read_into(&mut self.$field, val, $name) {
                                first.get_or_insert(e);
                            }
                        }
                        k += 1;
                    )*
                    let _ = k;
                }
                first.map_or(Ok(()), Err)
            }
        }
    };
}

/// Reads a document into a Go-typed value starting from `init` (Go's Unmarshal into a prepared struct).
pub fn unmarshal<T: FromGo>(b: &[u8], mut init: T) -> Result<T, Error> {
    let v = parse(b)?;
    init.read_into(&v, "")?;
    Ok(init)
}

// ---- writing, as Go's encoder ----

/// Appends `s` as a JSON string the way Go's encoder writes it (HTML-safe escaping on, as `json.Marshal` and `Encoder` do).
pub fn write_str(out: &mut String, s: &str) {
    use std::fmt::Write;
    out.push('"');
    let mut start = 0;
    for (i, c) in s.char_indices() {
        let esc: Option<&str> = match c {
            '"' => Some("\\\""),
            '\\' => Some("\\\\"),
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\t' => Some("\\t"),
            '\u{8}' => Some("\\b"),
            '\u{c}' => Some("\\f"),
            _ => None,
        };
        let needs_u = matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') || (c as u32) < 0x20;
        if esc.is_none() && !needs_u {
            continue;
        }
        out.push_str(&s[start..i]);
        match esc {
            Some(e) => out.push_str(e),
            None => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
        }
        start = i + c.len_utf8();
    }
    out.push_str(&s[start..]);
    out.push('"');
}

/// Writes a value compactly as Go would (members in the order held).
pub fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => write_str(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, it);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, it)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_value(out, it);
            }
            out.push('}');
        }
    }
}

/// Go's `json.MarshalIndent(v, "", indent)` layout: one member or element per line, `": "` after a key, empty arrays and
/// objects as `[]` and `{}`.
pub fn write_indented(out: &mut String, v: &Value, indent: &str) {
    fn go(out: &mut String, v: &Value, indent: &str, depth: usize) {
        let nl = |out: &mut String, d: usize| {
            out.push('\n');
            for _ in 0..d {
                out.push_str(indent);
            }
        };
        match v {
            Value::Array(items) if !items.is_empty() => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, depth + 1);
                    go(out, it, indent, depth + 1);
                }
                nl(out, depth);
                out.push(']');
            }
            Value::Object(m) if !m.is_empty() => {
                out.push('{');
                for (i, (k, it)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, depth + 1);
                    write_str(out, k);
                    out.push_str(": ");
                    go(out, it, indent, depth + 1);
                }
                nl(out, depth);
                out.push('}');
            }
            other => write_value(out, other),
        }
    }
    go(out, v, indent, 0)
}

/// Go's encoding of a float64 (`strconv.AppendFloat(f, 'f' or 'e', -1, 64)` with Go's cut-over at 1e21 and 1e-6).
pub fn write_f64(out: &mut String, f: f64) {
    if f == 0.0 {
        out.push('0');
        return;
    }
    let abs = f.abs();
    if (1e-6..1e21).contains(&abs) {
        // shortest representation that reads back, in plain notation: Rust's Display is that
        out.push_str(&format!("{f}"));
    } else {
        // Go: 'e' format, shortest; a positive exponent has at least two digits ("1e+21"), a negative one loses the
        // leading zero AppendFloat gives it ("1e-07" becomes "1e-7")
        let s = format!("{f:e}"); // e.g. "1e21", "1.5e-7"
        let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
        out.push_str(mant);
        out.push('e');
        match exp.strip_prefix('-') {
            Some(d) => {
                out.push('-');
                out.push_str(d);
            }
            None => {
                out.push('+');
                if exp.len() < 2 {
                    out.push('0');
                }
                out.push_str(exp);
            }
        }
    }
}

/// A small builder for objects written in a fixed field order, as Go writes a struct.
pub struct ObjectWriter<'a> {
    out: &'a mut String,
    first: bool,
}

impl<'a> ObjectWriter<'a> {
    pub fn new(out: &'a mut String) -> Self {
        out.push('{');
        ObjectWriter { out, first: true }
    }

    pub fn key(&mut self, k: &str) -> &mut String {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        write_str(self.out, k);
        self.out.push(':');
        self.out
    }

    pub fn str(&mut self, k: &str, v: &str) {
        let o = self.key(k);
        write_str(o, v);
    }

    pub fn raw(&mut self, k: &str, v: &str) {
        self.key(k).push_str(v);
    }

    pub fn map(&mut self, k: &str, m: &std::collections::BTreeMap<String, String>) {
        let o = self.key(k);
        o.push('{');
        for (i, (mk, mv)) in m.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            write_str(o, mk);
            o.push(':');
            write_str(o, mv);
        }
        o.push('}');
    }

    pub fn end(self) {
        self.out.push('}');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lone_surrogates_and_stray_bytes_read_as_go_reads_them() {
        let v = parse(br#""a\ud800b\udc00c\ud83d\ude00d\ud800\u0041""#).unwrap();
        assert_eq!(v, Value::String("a\u{FFFD}b\u{FFFD}c\u{1F600}d\u{FFFD}A".into()));
        let v = parse(b"\"x\xff\xe2\x84y\"").unwrap();
        assert_eq!(v, Value::String("x\u{FFFD}\u{FFFD}\u{FFFD}y".into()));
    }

    #[test]
    fn refuses_what_go_refuses() {
        for bad in [
            &b"{\"a\":1,}"[..],
            b"[1 2]",
            b"01",
            b"1.",
            b"-",
            b"\"\x01\"",
            b"{\"a\" 1}",
            b"\xef\xbb\xbf{}",
            b"{} {}",
            b"\"\\x\"",
            b"\"\\u12\"",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        assert!(parse(b" {\"a\":[1,2.5e-3,true,null,\"s\"]} \n").is_ok());
    }

    #[test]
    fn writes_as_go_writes() {
        // from Go: json.NewEncoder(os.Stdout).Encode(map[string]string{"a": "\b\f\n\r\t\x01<>&\u2028\x7f\xff é"})
        let mut s = String::new();
        write_str(&mut s, &gotext::lossy(b"\x08\x0c\n\r\t\x01<>&\xe2\x80\xa8\x7f\xff \xc3\xa9"));
        assert_eq!(s, "\"\\b\\f\\n\\r\\t\\u0001\\u003c\\u003e\\u0026\\u2028\x7f\u{FFFD} é\"");
    }

    #[test]
    fn struct_keys_match_as_in_go() {
        assert!(key_matches("Ring_Size", "ring_size"));
        assert!(key_matches("\u{17F}ession_id", "session_id"));
        assert!(!key_matches("ringsize", "ring_size"));
    }

    #[test]
    fn go_floats() {
        // from Go: json.Marshal of each
        for (f, want) in [
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (0.5, "0.5"),
            (123456.0, "123456"),
            (1.5e-7, "1.5e-7"),
            (-2.25, "-2.25"),
            (2.5e300, "2.5e+300"),
        ] {
            let mut s = String::new();
            write_f64(&mut s, f);
            assert_eq!(s, want);
        }
    }
}
