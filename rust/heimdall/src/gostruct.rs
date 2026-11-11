//! Go structs read and written back, described once as data (`Ty`). Some endpoints answer with a file another Go program
//! wrote, as Go's `json.Unmarshal` into a struct and `json.Encoder` back out make it: unknown keys dropped, keys matched
//! without regard to case, zero values written for missing fields, `omitempty` fields left out when empty, a time written
//! in RFC 3339 with its own offset, nil slices as `null`. `read` keeps Go's reading rules (null leaves a struct or a value
//! as it was and makes a slice or pointer nil; a duplicate key merges into the struct or element already read; a type
//! error is kept and the rest still read), so the bytes written are Go's for any file Go reads.

use crate::gojson::{self, Error, Value};
use crate::gotime::Time;

/// A Go type, as far as JSON sees it.
pub enum Ty {
    Str,
    Bool,
    /// int / int64
    Int,
    Uint32,
    Float,
    Time,
    Slice(&'static Ty),
    Ptr(&'static Ty),
    Struct(&'static str, &'static [Field]),
}

/// One field of a struct: its JSON name, its type, `omitempty`.
pub struct Field(pub &'static str, pub &'static Ty, pub bool);

/// A value of a `Ty`.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(String),
    /// A Go string with bytes that may not be UTF-8 (a cut note), written as Go writes it.
    Bytes(Vec<u8>),
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Time(Time),
    /// None: nil
    Slice(Option<Vec<Val>>),
    Ptr(Option<Box<Val>>),
    Struct(Vec<Val>),
}

/// The zero value.
pub fn zero(t: &Ty) -> Val {
    match t {
        Ty::Str => Val::Str(String::new()),
        Ty::Bool => Val::Bool(false),
        Ty::Int => Val::Int(0),
        Ty::Uint32 => Val::Uint(0),
        Ty::Float => Val::Float(0.0),
        Ty::Time => Val::Time(Time::default()),
        Ty::Slice(_) => Val::Slice(None),
        Ty::Ptr(_) => Val::Ptr(None),
        Ty::Struct(_, fs) => Val::Struct(fs.iter().map(|f| zero(f.1)).collect()),
    }
}

fn type_name(t: &Ty) -> String {
    match t {
        Ty::Str => "string".into(),
        Ty::Bool => "bool".into(),
        Ty::Int => "int".into(),
        Ty::Uint32 => "uint32".into(),
        Ty::Float => "float64".into(),
        Ty::Time => "time.Time".into(),
        Ty::Slice(e) => format!("[]{}", type_name(e)),
        Ty::Ptr(e) => format!("*{}", type_name(e)),
        Ty::Struct(n, _) => n.to_string(),
    }
}

/// Where a read is: the top type's name (Go's UnmarshalTypeError.Struct; "" for a slice) and the first error.
pub struct Ctx {
    pub top: &'static str,
    pub first: Option<Error>,
}

fn mismatch(v: &Value, t: &Ty, field: &str, top: &str) -> Error {
    let what = match v {
        // Go names the number only when it failed to read into a number type ("number 0.5" into int; "number" into string)
        Value::Number(n) if matches!(t, Ty::Int | Ty::Uint32 | Ty::Float) => format!("number {n}"),
        other => gojson::kind(other).to_string(),
    };
    let ty = type_name(t);
    if field.is_empty() {
        Error(format!("json: cannot unmarshal {what} into Go value of type {ty}"))
    } else if field.rsplit('.').next().is_some_and(|last| !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit())) {
        // a list's element: Go (1.27) leaves out "Go struct field" when the path ends at an index ("into Decisions.escalations.0")
        Error(format!("json: cannot unmarshal {what} into {top}.{field} of type {ty}"))
    } else {
        // Go 1.2x: the top struct's name, a dot, and the path from the top (slice indices included)
        Error(format!("json: cannot unmarshal {what} into Go struct field {top}.{field} of type {ty}"))
    }
}

/// Reads `v` into `into` as Go's decoder does; the first type error is kept in `cx` and everything else still read.
pub fn read(t: &Ty, v: &Value, into: &mut Val, field: &str, cx: &mut Ctx) {
    let top = cx.top;
    macro_rules! fail {
        ($e:expr) => {{
            let e = $e;
            cx.first.get_or_insert(e);
        }};
    }
    match (t, v) {
        (Ty::Slice(_), Value::Null) => *into = Val::Slice(None),
        (Ty::Ptr(_), Value::Null) => *into = Val::Ptr(None),
        (_, Value::Null) => {}
        (Ty::Str, Value::String(s)) => *into = Val::Str(s.clone()),
        (Ty::Bool, Value::Bool(b)) => *into = Val::Bool(*b),
        (Ty::Int, Value::Number(n)) => match n.parse::<i64>() {
            Ok(x) => *into = Val::Int(x),
            Err(_) => fail!(mismatch(v, t, field, top)),
        },
        (Ty::Uint32, Value::Number(n)) => match n.parse::<u32>() {
            Ok(x) => *into = Val::Uint(x as u64),
            Err(_) => fail!(mismatch(v, t, field, top)),
        },
        (Ty::Float, Value::Number(n)) => match n.parse::<f64>() {
            Ok(x) if x.is_finite() => *into = Val::Float(x),
            _ => fail!(mismatch(v, t, field, top)),
        },
        (Ty::Time, Value::String(s)) => match Time::parse_rfc3339(s) {
            Some(x) => *into = Val::Time(x),
            None => fail!(Error(format!("parsing time {} as RFC 3339: cannot parse", crate::gotext::quote(s)))),
        },
        // Go (1.27) names a wrong kind for a time as for any other type ("number into Go struct field X.until of type time.Time")
        (Ty::Time, _) => fail!(mismatch(v, t, field, top)),
        (Ty::Slice(e), Value::Array(items)) => {
            // Go decodes into the elements already there and zeroes none of them
            let mut old = match std::mem::replace(into, Val::Slice(None)) {
                Val::Slice(Some(o)) => o,
                _ => Vec::new(),
            };
            old.truncate(items.len());
            let mut out = Vec::with_capacity(items.len());
            let mut old = old.into_iter();
            for (i, it) in items.iter().enumerate() {
                let mut x = old.next().unwrap_or_else(|| zero(e));
                let path = if field.is_empty() { i.to_string() } else { format!("{field}.{i}") };
                read(e, it, &mut x, &path, cx);
                out.push(x);
            }
            *into = Val::Slice(Some(out));
        }
        (Ty::Ptr(e), _) => {
            let mut x = match std::mem::replace(into, Val::Ptr(None)) {
                Val::Ptr(Some(b)) => *b,
                _ => zero(e),
            };
            read(e, v, &mut x, field, cx);
            *into = Val::Ptr(Some(Box::new(x)));
        }
        (Ty::Struct(name, fs), Value::Object(_)) => {
            let names: Vec<&str> = fs.iter().map(|f| f.0).collect();
            let Ok(Some(members)) = gojson::struct_members(v, &names, name) else { return };
            let Val::Struct(vals) = into else { return };
            for (i, val) in members {
                let path = if field.is_empty() { fs[i].0.to_string() } else { format!("{field}.{}", fs[i].0) };
                read(fs[i].1, val, &mut vals[i], &path, cx);
            }
        }
        _ => fail!(mismatch(v, t, field, top)),
    }
}

/// Reads a whole document into a zero value of `t` (Go's `json.Unmarshal`): the value read (as far as it read) and the error.
pub fn unmarshal(t: &Ty, b: &[u8]) -> (Val, Option<Error>) {
    let mut out = zero(t);
    match gojson::parse(b) {
        Err(e) => (out, Some(e)),
        Ok(v) => {
            let top = match t {
                Ty::Struct(n, _) => n.rsplit('.').next().unwrap_or(n),
                _ => "",
            };
            let mut cx = Ctx { top, first: None };
            read(t, &v, &mut out, "", &mut cx);
            (out, cx.first)
        }
    }
}

/// A value Go's encoder refuses (a time outside years 0-9999): it then writes nothing at all.
#[derive(Debug)]
pub struct Unwritable;

fn empty(v: &Val) -> bool {
    match v {
        Val::Str(s) => s.is_empty(),
        Val::Bytes(b) => b.is_empty(),
        Val::Bool(b) => !b,
        Val::Int(i) => *i == 0,
        Val::Uint(u) => *u == 0,
        Val::Float(f) => *f == 0.0,
        Val::Slice(s) => s.as_ref().is_none_or(|s| s.is_empty()),
        Val::Ptr(p) => p.is_none(),
        Val::Time(_) | Val::Struct(_) => false,
    }
}

/// A Go string holding any bytes, as Go's encoder writes it: each byte that does not start valid UTF-8 as `�`.
pub fn write_bytes(out: &mut String, b: &[u8]) {
    out.push('"');
    let mut rest = b;
    loop {
        let (ok, bad) = match std::str::from_utf8(rest) {
            Ok(s) => (s, 0),
            Err(e) => {
                let ok = std::str::from_utf8(&rest[..e.valid_up_to()]).unwrap_or_default();
                (ok, e.error_len().unwrap_or(rest.len() - e.valid_up_to()))
            }
        };
        let mut tmp = String::new();
        gojson::write_str(&mut tmp, ok);
        out.push_str(&tmp[1..tmp.len() - 1]);
        for _ in 0..bad {
            out.push_str("\\ufffd");
        }
        rest = &rest[ok.len() + bad..];
        if rest.is_empty() {
            break;
        }
    }
    out.push('"');
}

fn newline(out: &mut String, indent: Option<&str>, depth: usize) {
    if let Some(ind) = indent {
        out.push('\n');
        for _ in 0..depth {
            out.push_str(ind);
        }
    }
}

/// Writes `v` as Go's encoder does (HTML-safe), compact or in `json.MarshalIndent`'s layout. Err: a time Go cannot write (a
/// year outside 0-9999; Go's encoder then writes nothing at all).
fn write_at(t: &Ty, v: &Val, out: &mut String, indent: Option<&str>, depth: usize) -> Result<(), Unwritable> {
    match (t, v) {
        (_, Val::Str(s)) => gojson::write_str(out, s),
        (_, Val::Bytes(b)) => write_bytes(out, b),
        (_, Val::Bool(b)) => out.push_str(if *b { "true" } else { "false" }),
        (_, Val::Int(i)) => out.push_str(&i.to_string()),
        (_, Val::Uint(u)) => out.push_str(&u.to_string()),
        (_, Val::Float(f)) => gojson::write_f64(out, *f),
        (_, Val::Time(x)) => {
            if !(0..=9999).contains(&x.civil().0) {
                return Err(Unwritable);
            }
            out.push('"');
            out.push_str(&x.rfc3339_nano());
            out.push('"');
        }
        (Ty::Slice(e), Val::Slice(s)) => match s {
            None => out.push_str("null"),
            Some(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline(out, indent, depth + 1);
                    write_at(e, it, out, indent, depth + 1)?;
                }
                if !items.is_empty() {
                    newline(out, indent, depth);
                }
                out.push(']');
            }
        },
        (Ty::Ptr(e), Val::Ptr(p)) => match p {
            None => out.push_str("null"),
            Some(x) => write_at(e, x, out, indent, depth)?,
        },
        (Ty::Struct(_, fs), Val::Struct(vals)) => {
            out.push('{');
            let mut first = true;
            for (f, x) in fs.iter().zip(vals) {
                if f.2 && empty(x) {
                    continue;
                }
                if !first {
                    out.push(',');
                }
                first = false;
                newline(out, indent, depth + 1);
                gojson::write_str(out, f.0);
                out.push_str(if indent.is_some() { ": " } else { ":" });
                write_at(f.1, x, out, indent, depth + 1)?;
            }
            if !first {
                newline(out, indent, depth);
            }
            out.push('}');
        }
        _ => return Err(Unwritable),
    }
    Ok(())
}

/// Writes `v` compact, as Go's encoder does.
pub fn write(t: &Ty, v: &Val, out: &mut String) -> Result<(), Unwritable> {
    write_at(t, v, out, None, 0)
}

/// The value as one JSON document (compact), or None when Go's encoder would fail.
pub fn to_json(t: &Ty, v: &Val) -> Option<String> {
    let mut s = String::new();
    write(t, v, &mut s).ok().map(|_| s)
}

/// Go's `json.MarshalIndent(v, "", indent)`.
pub fn to_json_indented(t: &Ty, v: &Val, indent: &str) -> Option<String> {
    let mut s = String::new();
    write_at(t, v, &mut s, Some(indent), 0).ok().map(|_| s)
}

/// A struct field's value by its JSON name (for code that reads a few fields).
pub fn field<'a>(t: &Ty, v: &'a Val, name: &str) -> Option<&'a Val> {
    match (t, v) {
        (Ty::Struct(_, fs), Val::Struct(vals)) => fs.iter().position(|f| f.0 == name).map(|i| &vals[i]),
        _ => None,
    }
}

/// A string field's text ("" when absent).
pub fn str_field<'a>(t: &Ty, v: &'a Val, name: &str) -> &'a str {
    match field(t, v, name) {
        Some(Val::Str(s)) => s,
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static INNER: Ty = Ty::Struct("x.Inner", &[Field("a", &Ty::Str, true), Field("n", &Ty::Int, false)]);
    static OUTER: Ty =
        Ty::Struct("x.Outer", &[Field("p", &Ty::Ptr(&INNER), true), Field("s", &Ty::Slice(&INNER), false), Field("t", &Ty::Time, true)]);

    #[test]
    fn reads_and_writes_as_go() {
        let (v, e) = unmarshal(&OUTER, br#"{"P":{"a":"x"},"p":{"n":2},"s":[{"n":1},{"N":2,"zz":1}],"t":"2026-11-05T10:00:00+01:00"}"#);
        assert!(e.is_none());
        assert_eq!(to_json(&OUTER, &v).unwrap(), r#"{"p":{"a":"x","n":2},"s":[{"n":1},{"n":2}],"t":"2026-11-05T10:00:00+01:00"}"#);
        let (v, e) = unmarshal(&OUTER, br#"{"s":null,"p":null,"t":null}"#);
        assert!(e.is_none());
        assert_eq!(to_json(&OUTER, &v).unwrap(), r#"{"s":null,"t":"0001-01-01T00:00:00Z"}"#);
        let (_, e) = unmarshal(&OUTER, br#"{"s":[{"n":"1"}]}"#);
        assert_eq!(e.unwrap().0, "json: cannot unmarshal string into Go struct field Outer.s.0.n of type int");
    }
}
