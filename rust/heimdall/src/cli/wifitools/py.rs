//! Python's behaviour, as far as the three Wi-Fi helpers lean on it, so the port does what the Python programs do on the same
//! input: `json.load` and `json.dump` (the C scanner's grammar, `NaN` and `Infinity`, duplicate keys, Python's float
//! `repr`, `ensure_ascii`), Python's values where a file or a tool's answer can hold any JSON (truthiness, `==`, `in`,
//! `for`, `str()`, `int()`), the string methods used on tools' output (`strip`, `split`, `splitlines`, `isprintable`), the
//! character classes of `re` (from `py_table.rs`, written by rust/pytools/pytable.py from the Python that runs the helpers)
//! and `subprocess.run` (text decoded as strict UTF-8 with universal newlines, the timeout killing the child).
//!
//! Where the Python program would stop with a traceback, the port returns a [`PyErr`] at the same point and stops with exit
//! code 1, so what was written before it is the same.

use std::fmt;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "py_table.rs"]
mod table;
pub use table::UNICODE;

/// A Python exception: its class and message.
#[derive(Clone, Debug, PartialEq)]
pub struct PyErr {
    pub kind: &'static str,
    pub msg: String,
}

impl PyErr {
    pub fn new(kind: &'static str, msg: impl Into<String>) -> PyErr {
        PyErr { kind, msg: msg.into() }
    }
    pub fn type_err(msg: impl Into<String>) -> PyErr {
        PyErr::new("TypeError", msg)
    }
    pub fn value(msg: impl Into<String>) -> PyErr {
        PyErr::new("ValueError", msg)
    }
    /// The OSError subclass Python raises for `e`.
    pub fn os(e: &std::io::Error, what: &str) -> PyErr {
        use std::io::ErrorKind::*;
        let kind = match e.kind() {
            NotFound => "FileNotFoundError",
            PermissionDenied => "PermissionError",
            AlreadyExists => "FileExistsError",
            IsADirectory => "IsADirectoryError",
            NotADirectory => "NotADirectoryError",
            _ => "OSError",
        };
        let errno = e.raw_os_error().unwrap_or(0);
        let text = std::io::Error::from_raw_os_error(errno).to_string();
        let text = text.split(" (os error").next().unwrap_or_default().to_string();
        PyErr::new(kind, format!("[Errno {errno}] {text}: {}", repr_str(what)))
    }
    /// Whether Python's `except OSError` catches it.
    pub fn is_os(&self) -> bool {
        matches!(
            self.kind,
            "OSError" | "FileNotFoundError" | "PermissionError" | "FileExistsError" | "IsADirectoryError" | "NotADirectoryError"
        )
    }
}

impl fmt::Display for PyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

pub type PyResult<T> = Result<T, PyErr>;

/// Stops as a Python program stops on an exception it does not catch: the exception on standard error (the last line of
/// Python's traceback), exit code 1.
pub fn traceback(prog: &str, e: &PyErr) -> i32 {
    eprintln!("{prog}: {e}");
    1
}

// ---- values

/// A Python value made by `json.load`. Integers keep their digits (Python's are unbounded); a NaN is always the one object
/// json's decoder makes for every `NaN`, which matters to `in` and to comparing lists (Python checks identity first).
#[derive(Clone, Debug)]
pub enum Val {
    None,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<Val>),
    Dict(Dict),
}

/// A dict: keys in the order they were first set, as Python keeps them.
#[derive(Clone, Debug, Default)]
pub struct Dict(pub Vec<(String, Val)>);

impl Dict {
    pub fn new() -> Dict {
        Dict(Vec::new())
    }
    pub fn get(&self, k: &str) -> Option<&Val> {
        self.0.iter().find(|(x, _)| x == k).map(|(_, v)| v)
    }
    pub fn get_mut(&mut self, k: &str) -> Option<&mut Val> {
        self.0.iter_mut().find(|(x, _)| x == k).map(|(_, v)| v)
    }
    /// `d[k] = v`: a key already there keeps its place.
    pub fn set(&mut self, k: &str, v: Val) {
        match self.get_mut(k) {
            Some(x) => *x = v,
            None => self.0.push((k.to_string(), v)),
        }
    }
    pub fn pop(&mut self, k: &str) -> Option<Val> {
        let i = self.0.iter().position(|(x, _)| x == k)?;
        Some(self.0.remove(i).1)
    }
    pub fn contains_key(&self, k: &str) -> bool {
        self.get(k).is_some()
    }
    /// `d.setdefault(k, v)`.
    pub fn setdefault(&mut self, k: &str, v: Val) -> &mut Val {
        if !self.contains_key(k) {
            self.0.push((k.to_string(), v));
        }
        self.get_mut(k).unwrap()
    }
    /// `dict(a, **b)`: a's items, then b's over them.
    pub fn merged(&self, b: &Dict) -> Dict {
        let mut d = self.clone();
        for (k, v) in &b.0 {
            d.set(k, v.clone());
        }
        d
    }
}

pub fn s(v: &str) -> Val {
    Val::Str(v.to_string())
}

impl Val {
    pub fn type_name(&self) -> &'static str {
        match self {
            Val::None => "NoneType",
            Val::Bool(_) => "bool",
            Val::Int(_) => "int",
            Val::Float(_) => "float",
            Val::Str(_) => "str",
            Val::List(_) => "list",
            Val::Dict(_) => "dict",
        }
    }

    /// Python's truth value.
    pub fn truthy(&self) -> bool {
        match self {
            Val::None => false,
            Val::Bool(b) => *b,
            Val::Int(i) => i != "0",
            Val::Float(f) => *f != 0.0,
            Val::Str(s) => !s.is_empty(),
            Val::List(l) => !l.is_empty(),
            Val::Dict(d) => !d.0.is_empty(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The dict behind `v.get(...)`, `v[...]` and friends; Python's AttributeError for anything else.
    pub fn dict(&self, attr: &str) -> PyResult<&Dict> {
        match self {
            Val::Dict(d) => Ok(d),
            v => Err(PyErr::new("AttributeError", format!("'{}' object has no attribute '{attr}'", v.type_name()))),
        }
    }

    /// `v.get(k, default)`.
    pub fn get(&self, k: &str, default: Val) -> PyResult<Val> {
        Ok(self.dict("get")?.get(k).cloned().unwrap_or(default))
    }

    /// `v[k]` on a dict (KeyError when missing); TypeError for a list or a string indexed by a key.
    pub fn index(&self, k: &str) -> PyResult<Val> {
        match self {
            Val::Dict(d) => d.get(k).cloned().ok_or_else(|| PyErr::new("KeyError", repr_str(k))),
            Val::List(_) => Err(PyErr::type_err("list indices must be integers or slices, not str")),
            Val::Str(_) => Err(PyErr::type_err("string indices must be integers, not 'str'")),
            v => Err(PyErr::type_err(format!("'{}' object is not subscriptable", v.type_name()))),
        }
    }

    /// `for x in v`.
    pub fn iter(&self) -> PyResult<Vec<Val>> {
        match self {
            Val::List(l) => Ok(l.clone()),
            Val::Dict(d) => Ok(d.0.iter().map(|(k, _)| Val::Str(k.clone())).collect()),
            Val::Str(s) => Ok(s.chars().map(|c| Val::Str(c.to_string())).collect()),
            v => Err(PyErr::type_err(format!("'{}' object is not iterable", v.type_name()))),
        }
    }

    /// `needle in self`.
    pub fn contains(&self, needle: &Val) -> PyResult<bool> {
        match self {
            Val::List(l) => Ok(l.iter().any(|x| eq_in(x, needle))),
            Val::Dict(d) => match needle {
                Val::Str(k) => Ok(d.contains_key(k)),
                Val::List(_) | Val::Dict(_) => Err(PyErr::type_err(format!("unhashable type: '{}'", needle.type_name()))),
                _ => Ok(false),
            },
            Val::Str(h) => match needle {
                Val::Str(n) => Ok(h.contains(n.as_str())),
                n => Err(PyErr::type_err(format!("'in <string>' requires string as left operand, not {}", n.type_name()))),
            },
            v => Err(PyErr::type_err(format!("argument of type '{}' is not a container or iterable", v.type_name()))),
        }
    }

    /// `len(v)`.
    pub fn py_len(&self) -> PyResult<usize> {
        match self {
            Val::List(l) => Ok(l.len()),
            Val::Dict(d) => Ok(d.0.len()),
            Val::Str(s) => Ok(s.chars().count()),
            v => Err(PyErr::type_err(format!("object of type '{}' has no len()", v.type_name()))),
        }
    }

    /// `v.upper()` (strings only).
    pub fn upper(&self) -> PyResult<String> {
        match self {
            Val::Str(s) => Ok(upper(s)),
            v => Err(PyErr::new("AttributeError", format!("'{}' object has no attribute 'upper'", v.type_name()))),
        }
    }
}

fn numeric(v: &Val) -> Option<Result<String, f64>> {
    match v {
        Val::Bool(b) => Some(Ok(if *b { "1".into() } else { "0".into() })),
        Val::Int(i) => Some(Ok(i.clone())),
        Val::Float(f) => Some(Err(*f)),
        _ => None,
    }
}

/// An integral float's exact digits (Python compares ints and floats exactly).
fn float_digits(f: f64) -> Option<String> {
    if !f.is_finite() || f.fract() != 0.0 {
        return None;
    }
    let s = format!("{f:.0}");
    Some(if s == "-0" { "0".into() } else { s })
}

fn eq_impl(a: &Val, b: &Val, nested: bool) -> bool {
    match (a, b) {
        (Val::None, Val::None) => true,
        (Val::Str(x), Val::Str(y)) => x == y,
        (Val::List(x), Val::List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq_impl(p, q, true)),
        (Val::Dict(x), Val::Dict(y)) => x.0.len() == y.0.len() && x.0.iter().all(|(k, v)| y.get(k).is_some_and(|w| eq_impl(v, w, true))),
        _ => match (numeric(a), numeric(b)) {
            (Some(Ok(i)), Some(Ok(j))) => i == j,
            (Some(Ok(i)), Some(Err(f))) | (Some(Err(f)), Some(Ok(i))) => float_digits(f).is_some_and(|d| d == i),
            // every NaN json makes is the same object: equal where Python looks at identity first
            (Some(Err(f)), Some(Err(g))) => f == g || (nested && f.is_nan() && g.is_nan()),
            _ => false,
        },
    }
}

/// `a == b`.
pub fn eq(a: &Val, b: &Val) -> bool {
    eq_impl(a, b, false)
}

/// Equality as `in` and container comparison see it (identity first).
pub fn eq_in(a: &Val, b: &Val) -> bool {
    eq_impl(a, b, true)
}

/// `int(v)`, as its decimal digits.
pub fn int(v: &Val) -> PyResult<String> {
    match v {
        Val::Bool(b) => Ok(if *b { "1".into() } else { "0".into() }),
        Val::Int(i) => Ok(i.clone()),
        Val::Float(f) if f.is_nan() => Err(PyErr::value("cannot convert float NaN to integer")),
        Val::Float(f) if f.is_infinite() => Err(PyErr::new("OverflowError", "cannot convert float infinity to integer")),
        Val::Float(f) => Ok(float_digits(f.trunc()).unwrap()),
        Val::Str(s) => int_str(s),
        v => {
            Err(PyErr::type_err(format!("int() argument must be a string, a bytes-like object or a real number, not '{}'", v.type_name())))
        }
    }
}

/// Python's limit on the digits of an integer read from text.
pub const MAX_STR_DIGITS: usize = 4300;

/// `int(s)` of a string, as CPython reads it: other scripts' digits and whitespace mapped to ASCII first (a character that
/// is neither ends the text), then ASCII spaces around, a sign, digits with single underscores between them.
pub fn int_str(text: &str) -> PyResult<String> {
    let bad = || PyErr::value(format!("invalid literal for int() with base 10: {}", repr_str(text)));
    let mut t = String::new();
    for c in text.chars() {
        if (c as u32) < 127 {
            t.push(c);
        } else if is_space(c) {
            t.push(' ');
        } else if let Some(d) = decimal_value(c) {
            t.push(char::from(b'0' + d as u8));
        } else {
            t.push('?');
            break;
        }
    }
    let t = t.trim_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (neg, body) = match t.chars().next() {
        Some('-') => (true, &t[1..]),
        Some('+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut digits = String::new();
    let mut prev_digit = false;
    let mut last_underscore = false;
    for c in body.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            prev_digit = true;
            last_underscore = false;
        } else if c == '_' && prev_digit {
            prev_digit = false;
            last_underscore = true;
        } else {
            return Err(bad());
        }
    }
    if digits.is_empty() || last_underscore {
        return Err(bad());
    }
    if digits.len() > MAX_STR_DIGITS {
        return Err(PyErr::value(format!(
            "Exceeds the limit ({MAX_STR_DIGITS} digits) for integer string conversion: value has {} digits; use sys.set_int_max_str_digits() to increase the limit",
            digits.len()
        )));
    }
    let d = digits.trim_start_matches('0');
    Ok(match (d.is_empty(), neg) {
        (true, _) => "0".into(),
        (false, true) => format!("-{d}"),
        (false, false) => d.to_string(),
    })
}

// ---- text

/// `str.isspace()`.
pub fn is_space(c: char) -> bool {
    matches!(c, '\t'..='\r' | '\x1c'..=' ' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

fn in_table(t: &[(u32, u32)], c: char) -> bool {
    let c = c as u32;
    t.binary_search_by(|&(a, b)| {
        if b < c {
            std::cmp::Ordering::Less
        } else if a > c {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    })
    .is_ok()
}

/// `str.isprintable()` of one character.
pub fn is_printable(c: char) -> bool {
    in_table(table::PRINTABLE, c)
}

/// A word character to Python's `re` on text (`\w`).
pub fn is_word(c: char) -> bool {
    in_table(table::WORD, c)
}

/// The value of a decimal digit of any script (`\d`, `int()`), None for anything else.
pub fn decimal_value(c: char) -> Option<u32> {
    let x = c as u32;
    let t = table::DECIMAL;
    let i = t.partition_point(|&(_, b)| b < x);
    let &(a, b) = t.get(i)?;
    (a <= x && x <= b).then(|| (x - a) % 10)
}

/// `s.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `s.strip(chars)`.
pub fn strip_chars<'a>(s: &'a str, chars: &str) -> &'a str {
    s.trim_matches(|c| chars.contains(c))
}

/// `s.split()`.
pub fn split_ws(s: &str) -> Vec<&str> {
    s.split(is_space).filter(|x| !x.is_empty()).collect()
}

/// `s.splitlines()`: every line boundary Python knows, `\r\n` as one.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}') {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(_, '\n')) = it.peek() {
                    it.next();
                    end += 1;
                }
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `s.upper()` (Rust's full Unicode mapping; Python's tables are the Unicode version in `UNICODE`).
pub fn upper(s: &str) -> String {
    s.to_uppercase()
}

/// `str.isprintable()` filter and a cut by characters: `"".join(c for c in s if c.isprintable())[:n]`.
pub fn printable_prefix(s: &str, n: usize) -> String {
    s.chars().filter(|&c| is_printable(c)).take(n).collect()
}

/// `s[:n]` by characters.
pub fn prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// ---- JSON

/// Why `json.load` failed: Python raises ValueError (or RecursionError for nesting deeper than its C stack allows).
#[derive(Debug, PartialEq)]
pub enum JsonErr {
    Value,
    Recursion,
}

/// How deep the reader goes before it gives up as Python's does (Python's own depth depends on its C stack: tens of
/// thousands on this computer; no file the helpers read comes near either).
pub const MAX_DEPTH: usize = 10_000;

struct Parser<'a> {
    b: &'a [u8],
    s: &'a str,
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn lit(&mut self, w: &str) -> bool {
        if self.s[self.i..].starts_with(w) {
            self.i += w.len();
            true
        } else {
            false
        }
    }
    fn value(&mut self) -> Result<Val, JsonErr> {
        let Some(&c) = self.b.get(self.i) else { return Err(JsonErr::Value) };
        match c {
            b'"' => {
                self.i += 1;
                return self.string().map(Val::Str);
            }
            b'{' | b'[' => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err(JsonErr::Recursion);
                }
                self.i += 1;
                let v = if c == b'{' { self.object() } else { self.array() };
                self.depth -= 1;
                return v;
            }
            b'n' if self.lit("null") => return Ok(Val::None),
            b't' if self.lit("true") => return Ok(Val::Bool(true)),
            b'f' if self.lit("false") => return Ok(Val::Bool(false)),
            b'N' if self.lit("NaN") => return Ok(Val::Float(f64::NAN)),
            b'I' if self.lit("Infinity") => return Ok(Val::Float(f64::INFINITY)),
            b'-' if self.lit("-Infinity") => return Ok(Val::Float(f64::NEG_INFINITY)),
            _ => {}
        }
        self.number()
    }
    fn digits(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
    }
    fn number(&mut self) -> Result<Val, JsonErr> {
        let start = self.i;
        let b = self.b;
        if b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match b.get(self.i) {
            Some(b'1'..=b'9') => self.digits(),
            Some(b'0') => self.i += 1,
            _ => return Err(JsonErr::Value),
        }
        let mut float = false;
        if b.get(self.i) == Some(&b'.') && b.get(self.i + 1).is_some_and(u8::is_ascii_digit) {
            float = true;
            self.i += 1;
            self.digits();
        }
        if matches!(b.get(self.i), Some(b'e' | b'E')) {
            let e = self.i;
            self.i += 1;
            if matches!(b.get(self.i), Some(b'-' | b'+')) {
                self.i += 1;
            }
            let d = self.i;
            self.digits();
            if self.i > d {
                float = true;
            } else {
                self.i = e;
            }
        }
        let text = &self.s[start..self.i];
        if float {
            return Ok(Val::Float(text.parse::<f64>().map_err(|_| JsonErr::Value)?));
        }
        let neg = text.starts_with('-');
        let d = text.trim_start_matches('-');
        if d.len() > MAX_STR_DIGITS {
            return Err(JsonErr::Value);
        }
        Ok(Val::Int(if neg && d != "0" { text.to_string() } else { d.to_string() }))
    }
    fn hex4(&self, at: usize) -> Result<u32, JsonErr> {
        let h = self.b.get(at..at + 4).ok_or(JsonErr::Value)?;
        let mut v = 0;
        for &c in h {
            v = v * 16 + (c as char).to_digit(16).ok_or(JsonErr::Value)?;
        }
        Ok(v)
    }
    fn string(&mut self) -> Result<String, JsonErr> {
        let mut out = String::new();
        loop {
            let rest = &self.s[self.i..];
            let mut chars = rest.char_indices();
            let mut stop = None;
            for (j, c) in chars.by_ref() {
                if c == '"' || c == '\\' {
                    stop = Some((j, c));
                    break;
                }
                if (c as u32) < 0x20 {
                    return Err(JsonErr::Value); // strict: no raw control characters
                }
            }
            let Some((j, c)) = stop else { return Err(JsonErr::Value) };
            out.push_str(&rest[..j]);
            self.i += j + 1;
            if c == '"' {
                return Ok(out);
            }
            let Some(&e) = self.b.get(self.i) else { return Err(JsonErr::Value) };
            self.i += 1;
            match e {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let mut c = self.hex4(self.i)?;
                    self.i += 4;
                    if (0xd800..0xdc00).contains(&c) && self.i + 6 < self.b.len() && self.b[self.i] == b'\\' && self.b[self.i + 1] == b'u' {
                        let c2 = self.hex4(self.i + 2)?;
                        if (0xdc00..0xe000).contains(&c2) {
                            c = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
                            self.i += 6;
                        }
                    }
                    // a lone surrogate: Python keeps it in the string; a Rust string cannot hold one, so the file
                    // reads as damaged (neither program writes one)
                    out.push(char::from_u32(c).ok_or(JsonErr::Value)?);
                }
                _ => return Err(JsonErr::Value),
            }
        }
    }
    fn object(&mut self) -> Result<Val, JsonErr> {
        let mut d = Dict::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Val::Dict(d));
        }
        loop {
            if self.b.get(self.i) != Some(&b'"') {
                return Err(JsonErr::Value);
            }
            self.i += 1;
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(JsonErr::Value);
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            d.set(&k, v);
            self.ws();
            match self.b.get(self.i) {
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Val::Dict(d));
                }
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                }
                _ => return Err(JsonErr::Value),
            }
        }
    }
    fn array(&mut self) -> Result<Val, JsonErr> {
        let mut l = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Val::List(l));
        }
        loop {
            l.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b']') => {
                    self.i += 1;
                    return Ok(Val::List(l));
                }
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                }
                _ => return Err(JsonErr::Value),
            }
        }
    }
}

/// `json.loads(s)`.
pub fn loads(s: &str) -> Result<Val, JsonErr> {
    if s.starts_with('\u{feff}') {
        return Err(JsonErr::Value); // "Unexpected UTF-8 BOM"
    }
    let mut p = Parser { b: s.as_bytes(), s, i: 0, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != s.len() {
        return Err(JsonErr::Value);
    }
    Ok(v)
}

/// What `json.load(open(path))` ends in.
#[derive(Debug)]
pub enum Load {
    Ok(Val),
    /// OSError (missing, unreadable, a folder)
    Os(PyErr),
    /// ValueError (not UTF-8, not JSON)
    Value,
    /// RecursionError: Python does not catch it
    Recursion,
}

/// `with open(path) as f: json.load(f)` (text mode, UTF-8, strict).
pub fn load_file(path: &Path) -> Load {
    let b = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return Load::Os(PyErr::os(&e, &path.to_string_lossy())),
    };
    let Ok(text) = String::from_utf8(b) else { return Load::Value };
    match loads(&text) {
        Ok(v) => Load::Ok(v),
        Err(JsonErr::Value) => Load::Value,
        Err(JsonErr::Recursion) => Load::Recursion,
    }
}

/// The helpers' `load(path, {})`: the dict in the file; an empty one when the file does not read, is not JSON, or (since
/// 2026-11-11, in the Python too) holds JSON that is not an object.
pub fn load_dict(path: &Path) -> PyResult<Dict> {
    match load_file(path) {
        Load::Ok(Val::Dict(d)) => Ok(d),
        Load::Recursion => Err(PyErr::new("RecursionError", "maximum recursion depth exceeded while decoding a JSON document")),
        _ => Ok(Dict::new()),
    }
}

/// Python's `repr(float)`: the shortest digits that read back, fixed notation from 1e-4 up to 1e16, exponent otherwise.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let split = |e: &str| -> (String, i32) {
        let (mant, exp) = e.split_once('e').unwrap();
        (mant.chars().filter(|c| *c != '.').collect(), exp.parse().unwrap())
    };
    let (mut digits, mut exp) = split(&format!("{:e}", f.abs()));
    // of two shortest forms equally near, Python's dtoa takes the even one: the value rounded to as many digits (ties to
    // even) wins whenever it reads back
    if digits.len() > 1 {
        let alt = format!("{:.*e}", digits.len() - 1, f.abs());
        if alt.parse::<f64>() == Ok(f.abs()) {
            (digits, exp) = split(&alt);
        }
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    let decpt = exp + 1;
    let n = digits.len() as i32;
    if decpt <= -4 || decpt > 16 {
        let m = if n == 1 { digits.clone() } else { format!("{}.{}", &digits[..1], &digits[1..]) };
        let x = decpt - 1;
        return format!("{sign}{m}e{}{:02}", if x < 0 { '-' } else { '+' }, x.abs());
    }
    if decpt <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt >= n {
        format!("{sign}{digits}{}.0", "0".repeat((decpt - n) as usize))
    } else {
        format!("{sign}{}.{}", &digits[..decpt as usize], &digits[decpt as usize..])
    }
}

fn json_float(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f.is_infinite() {
        if f > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else {
        float_repr(f)
    }
}

/// A string as `json.dumps` writes it (`ensure_ascii`: everything outside space..`~` escaped).
pub fn json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn dump_into(v: &Val, indent: Option<usize>, level: usize, out: &mut String) {
    match v {
        Val::None => out.push_str("null"),
        Val::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Val::Int(i) => out.push_str(i),
        Val::Float(f) => out.push_str(&json_float(*f)),
        Val::Str(s) => json_str(s, out),
        Val::List(l) if l.is_empty() => out.push_str("[]"),
        Val::Dict(d) if d.0.is_empty() => out.push_str("{}"),
        Val::List(_) | Val::Dict(_) => {
            let (open, close) = if matches!(v, Val::List(_)) { ('[', ']') } else { ('{', '}') };
            out.push(open);
            let items: Vec<(Option<&str>, &Val)> = match v {
                Val::List(l) => l.iter().map(|x| (None, x)).collect(),
                Val::Dict(d) => d.0.iter().map(|(k, x)| (Some(k.as_str()), x)).collect(),
                _ => unreachable!(),
            };
            for (n, (k, x)) in items.into_iter().enumerate() {
                match indent {
                    Some(w) => {
                        if n > 0 {
                            out.push(',');
                        }
                        out.push('\n');
                        out.push_str(&" ".repeat(w * (level + 1)));
                    }
                    None if n > 0 => out.push_str(", "),
                    None => {}
                }
                if let Some(k) = k {
                    json_str(k, out);
                    out.push_str(": ");
                }
                dump_into(x, indent, level + 1, out);
            }
            if let Some(w) = indent {
                out.push('\n');
                out.push_str(&" ".repeat(w * level));
            }
            out.push(close);
        }
    }
}

/// `json.dumps(v)` (`indent` None) or `json.dumps(v, indent=n)`.
pub fn dumps(v: &Val, indent: Option<usize>) -> String {
    let mut out = String::new();
    dump_into(v, indent, 0, &mut out);
    out
}

/// `repr(s)` of a string.
pub fn repr_str(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            _ if c == q || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if (c as u32) < 0x20 || c == '\x7f' => out.push_str(&format!("\\x{:02x}", c as u32)),
            _ if (c as u32) < 0x7f || is_printable(c) => out.push(c),
            _ if (c as u32) <= 0xff => out.push_str(&format!("\\x{:02x}", c as u32)),
            _ if (c as u32) <= 0xffff => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(q);
    out
}

/// `repr(v)`.
pub fn repr(v: &Val) -> String {
    match v {
        Val::None => "None".into(),
        Val::Bool(b) => if *b { "True" } else { "False" }.into(),
        Val::Int(i) => i.clone(),
        Val::Float(f) => float_repr(*f),
        Val::Str(s) => repr_str(s),
        Val::List(l) => format!("[{}]", l.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Val::Dict(d) => format!("{{{}}}", d.0.iter().map(|(k, x)| format!("{}: {}", repr_str(k), repr(x))).collect::<Vec<_>>().join(", ")),
    }
}

/// `str(v)`.
pub fn str_of(v: &Val) -> String {
    match v {
        Val::Str(s) => s.clone(),
        v => repr(v),
    }
}

// ---- files

/// `os.makedirs(path, exist_ok=True)`.
pub fn makedirs(path: &Path) -> PyResult<()> {
    if path.as_os_str().is_empty() {
        return Err(PyErr::new("FileNotFoundError", "[Errno 2] No such file or directory: ''"));
    }
    match std::fs::create_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) => Err(PyErr::os(&e, &path.to_string_lossy())),
    }
}

/// `open(path, "w").write(text)`.
pub fn write_text(path: &Path, text: &str) -> PyResult<()> {
    std::fs::write(path, text).map_err(|e| PyErr::os(&e, &path.to_string_lossy()))
}

/// `open(path, "a").write(text)`.
pub fn append_text(path: &Path, text: &str) -> PyResult<()> {
    let mut f = std::fs::OpenOptions::new().append(true).create(true).open(path).map_err(|e| PyErr::os(&e, &path.to_string_lossy()))?;
    f.write_all(text.as_bytes()).map_err(|e| PyErr::os(&e, &path.to_string_lossy()))
}

/// `os.chmod(path, mode)`.
pub fn chmod(path: &Path, mode: u32) -> PyResult<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| PyErr::os(&e, &path.to_string_lossy()))
}

/// `os.replace(a, b)`.
pub fn replace(a: &Path, b: &Path) -> PyResult<()> {
    std::fs::rename(a, b).map_err(|e| PyErr::os(&e, &a.to_string_lossy()))
}

/// `os.path.dirname(p)` on a path's bytes.
pub fn dirname_bytes(p: &[u8]) -> &[u8] {
    let i = p.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1);
    let head = &p[..i];
    if head.iter().all(|&c| c == b'/') {
        return head;
    }
    let mut e = head.len();
    while e > 0 && head[e - 1] == b'/' {
        e -= 1;
    }
    &head[..e]
}

/// `os.path.dirname(p)`.
pub fn dirname(p: &str) -> &str {
    std::str::from_utf8(dirname_bytes(p.as_bytes())).unwrap()
}

/// `time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())`.
pub fn utc_stamp() -> String {
    let (y, mo, d, h, mi, se) = crate::gotime::Time::now().utc().civil();
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}Z")
}

// ---- subprocess

/// What `subprocess.run` returned.
#[derive(Debug, Default)]
pub struct Done {
    /// the exit code; minus the signal for a child killed by one, as Python's returncode
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// How a child is started.
pub struct Run<'a> {
    pub argv: &'a [String],
    /// None: this process's environment
    pub env: Option<&'a [(&'a str, &'a str)]>,
    /// `input=`: written to its standard input (otherwise the child shares ours)
    pub input: Option<&'a str>,
    /// `capture_output=True, text=True`
    pub capture: bool,
    pub timeout: Option<Duration>,
}

/// The environment the guard and the check give their tools.
pub const TOOL_ENV: &[(&str, &str)] = &[("PATH", "/usr/bin:/bin"), ("LANG", "C")];

/// Output as `text=True` gives it: strict UTF-8, `\r\n` and `\r` as `\n`.
pub fn text(b: Vec<u8>) -> PyResult<String> {
    let s = String::from_utf8(b).map_err(|e| {
        let at = e.utf8_error().valid_up_to();
        PyErr::new("UnicodeDecodeError", format!("'utf-8' codec can't decode byte 0x{:02x} in position {at}", e.as_bytes()[at]))
    })?;
    Ok(if s.contains('\r') { s.replace("\r\n", "\n").replace('\r', "\n") } else { s })
}

/// `subprocess.run(...)`.
pub fn run(r: &Run) -> PyResult<Done> {
    if r.argv.iter().any(|a| a.contains('\0')) {
        return Err(PyErr::value("embedded null byte"));
    }
    let mut cmd = Command::new(&r.argv[0]);
    cmd.args(&r.argv[1..]);
    if let Some(env) = r.env {
        cmd.env_clear();
        for (k, v) in env {
            cmd.env(k, v);
        }
    }
    cmd.stdin(if r.input.is_some() { Stdio::piped() } else { Stdio::inherit() });
    if r.capture {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(|e| PyErr::os(&e, &r.argv[0]))?;
    let pidfd = rustix::process::Pid::from_raw(child.id() as i32)
        .and_then(|p| rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty()).ok());
    let feeder = r.input.map(|t| {
        let mut w = child.stdin.take().unwrap();
        let t = t.as_bytes().to_vec();
        std::thread::spawn(move || {
            let _ = w.write_all(&t);
        })
    });
    let reader = |p: Option<Box<dyn Read + Send>>| {
        p.map(|mut p| {
            std::thread::spawn(move || {
                let mut b = Vec::new();
                let _ = p.read_to_end(&mut b);
                b
            })
        })
    };
    let out = reader(child.stdout.take().map(|x| Box::new(x) as Box<dyn Read + Send>));
    let err = reader(child.stderr.take().map(|x| Box::new(x) as Box<dyn Read + Send>));
    // wait for the child, at most until the deadline (its pidfd becomes readable when it exits)
    let deadline = r.timeout.map(|t| Instant::now() + t);
    let exited = match (&pidfd, deadline) {
        (Some(fd), Some(dl)) => loop {
            let left = dl.saturating_duration_since(Instant::now());
            let ts = rustix::event::Timespec { tv_sec: left.as_secs() as i64, tv_nsec: left.subsec_nanos() as i64 };
            let mut fds = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
            match rustix::event::poll(&mut fds, Some(&ts)) {
                Ok(0) => break false,
                Ok(_) => break true,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => break true,
            }
        },
        (None, Some(dl)) => loop {
            if child.try_wait().ok().flatten().is_some() {
                break true;
            }
            if Instant::now() >= dl {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        },
        _ => true,
    };
    if !exited {
        match &pidfd {
            Some(fd) => {
                let _ = rustix::process::pidfd_send_signal(fd, rustix::process::Signal::KILL);
            }
            None => {
                let _ = child.kill();
            }
        }
        let _ = child.wait();
        return Err(PyErr::new(
            "TimeoutExpired",
            format!(
                "Command '{}' timed out after {} seconds",
                repr(&Val::List(r.argv.iter().map(|a| s(a)).collect())),
                r.timeout.unwrap().as_secs()
            ),
        ));
    }
    let status = child.wait().map_err(|e| PyErr::os(&e, &r.argv[0]))?;
    if let Some(f) = feeder {
        let _ = f.join();
    }
    use std::os::unix::process::ExitStatusExt;
    let code = status.code().unwrap_or_else(|| -status.signal().unwrap_or(0));
    let stdout = out.map(|t| t.join().unwrap_or_default()).unwrap_or_default();
    let stderr = err.map(|t| t.join().unwrap_or_default()).unwrap_or_default();
    if !r.capture {
        return Ok(Done { code, ..Done::default() });
    }
    Ok(Done { code, stdout: text(stdout)?, stderr: text(stderr)? })
}

/// `subprocess.run(argv, capture_output=True, text=True, timeout=t, env=ENV)`.
pub fn capture(argv: &[String], timeout: Option<Duration>) -> PyResult<Done> {
    run(&Run { argv, env: Some(TOOL_ENV), input: None, capture: true, timeout })
}

/// Words as a program's arguments.
pub fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}
