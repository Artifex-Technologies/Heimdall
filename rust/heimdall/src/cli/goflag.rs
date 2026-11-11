//! Go's `flag` package as the Go heimdalld's commands use it (`flag.NewFlagSet(name, flag.ContinueOnError)`): the same
//! spellings accepted (`-x v`, `--x v`, `-x=v`, a bool alone or `-x=false`, `--` ends the flags, the first word that is not a
//! flag ends them too), the same values read (Go's `strconv.ParseInt` with base 0, `ParseBool`, `time.ParseDuration`), and
//! the same messages on standard error when a flag is wrong ("flag provided but not defined: -x", then "Usage of NAME:" and
//! the flags as Go's `PrintDefaults` lists them). `-h` and `-help` print the usage and fail, as in Go.

use crate::gotext::quote;
use std::collections::BTreeMap;
use std::io::Write;

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Str(String),
    Bool(bool),
    Int(i64),
    Duration(i64),
    List(Vec<String>),
}

impl Val {
    /// Go's `Value.String()` (what `DefValue` holds).
    fn go_string(&self) -> String {
        match self {
            Val::Str(s) => s.clone(),
            Val::Bool(b) => b.to_string(),
            Val::Int(i) => i.to_string(),
            Val::Duration(d) => crate::gotext::duration(*d),
            // fmt.Sprint of a []string: [a b c]
            Val::List(l) => format!("[{}]", l.join(" ")),
        }
    }
    /// The name `UnquoteUsage` gives the value in the usage list.
    fn type_name(&self) -> &'static str {
        match self {
            Val::Str(_) => "string",
            Val::Bool(_) => "",
            Val::Int(_) => "int",
            Val::Duration(_) => "duration",
            Val::List(_) => "value",
        }
    }
    fn zero(&self) -> Val {
        match self {
            Val::Str(_) => Val::Str(String::new()),
            Val::Bool(_) => Val::Bool(false),
            Val::Int(_) => Val::Int(0),
            Val::Duration(_) => Val::Duration(0),
            Val::List(_) => Val::List(Vec::new()),
        }
    }
}

/// A replacement for the default usage (Go's `fs.Usage`).
type UsageFn = Box<dyn Fn(&FlagSet)>;

struct Def {
    usage: String,
    default: Val,
    value: Val,
}

/// A set of flags, parsed as Go's `flag.FlagSet` with `ContinueOnError`.
pub struct FlagSet {
    name: String,
    defs: BTreeMap<String, Def>,
    args: Vec<String>,
    actual: Vec<String>,
    usage: Option<UsageFn>,
    /// The error Go's `Parse` returned, as text (`error()`).
    error: std::cell::RefCell<String>,
}

/// Parsing failed; the message and the usage are already on standard error (Go's `Parse` returning an error, or ErrHelp).
#[derive(Debug, PartialEq)]
pub struct Failed;

impl FlagSet {
    pub fn new(name: &str) -> FlagSet {
        FlagSet {
            name: name.to_string(),
            defs: BTreeMap::new(),
            args: Vec::new(),
            actual: Vec::new(),
            usage: None,
            error: std::cell::RefCell::new(String::new()),
        }
    }

    fn define(&mut self, name: &str, v: Val, usage: &str) {
        self.defs.insert(name.to_string(), Def { usage: usage.to_string(), default: v.clone(), value: v });
    }
    /// `fs.String(name, default, usage)`
    pub fn string(&mut self, name: &str, default: &str, usage: &str) {
        self.define(name, Val::Str(default.into()), usage)
    }
    /// `fs.Bool(name, default, usage)`
    pub fn bool(&mut self, name: &str, default: bool, usage: &str) {
        self.define(name, Val::Bool(default), usage)
    }
    /// `fs.Int` and `fs.Int64` (both 64 bits on the computers Heimdall runs on).
    pub fn int(&mut self, name: &str, default: i64, usage: &str) {
        self.define(name, Val::Int(default), usage)
    }
    /// `fs.Duration(name, default, usage)`, in nanoseconds.
    pub fn duration(&mut self, name: &str, default: i64, usage: &str) {
        self.define(name, Val::Duration(default), usage)
    }
    /// `fs.Var(&list, name, usage)` with a list flag that appends each use (cmd/heimdalld's `listFlag`).
    pub fn list(&mut self, name: &str, usage: &str) {
        self.define(name, Val::List(Vec::new()), usage)
    }
    /// `fs.Usage = ...`: printed instead of the default usage when a flag is wrong.
    pub fn set_usage(&mut self, f: impl Fn(&FlagSet) + 'static) {
        self.usage = Some(Box::new(f));
    }

    pub fn get_str(&self, name: &str) -> String {
        match self.defs.get(name).map(|d| &d.value) {
            Some(Val::Str(s)) => s.clone(),
            _ => panic!("no string flag {name}"),
        }
    }
    pub fn get_bool(&self, name: &str) -> bool {
        match self.defs.get(name).map(|d| &d.value) {
            Some(Val::Bool(b)) => *b,
            _ => panic!("no bool flag {name}"),
        }
    }
    pub fn get_int(&self, name: &str) -> i64 {
        match self.defs.get(name).map(|d| &d.value) {
            Some(Val::Int(i)) => *i,
            _ => panic!("no int flag {name}"),
        }
    }
    /// Nanoseconds.
    pub fn get_duration(&self, name: &str) -> i64 {
        match self.defs.get(name).map(|d| &d.value) {
            Some(Val::Duration(d)) => *d,
            _ => panic!("no duration flag {name}"),
        }
    }
    pub fn get_list(&self, name: &str) -> Vec<String> {
        match self.defs.get(name).map(|d| &d.value) {
            Some(Val::List(l)) => l.clone(),
            _ => panic!("no list flag {name}"),
        }
    }
    /// The words after the flags (`fs.Args()`).
    pub fn args(&self) -> &[String] {
        &self.args
    }
    pub fn narg(&self) -> usize {
        self.args.len()
    }
    /// Whether the flag was given (`fs.Visit`).
    pub fn is_set(&self, name: &str) -> bool {
        self.actual.iter().any(|a| a == name)
    }

    /// Go's `PrintDefaults`, as text.
    pub fn defaults(&self) -> String {
        let mut out = String::new();
        for (name, d) in &self.defs {
            let mut b = format!("  -{name}");
            let (vname, usage) = unquote_usage(&d.default, &d.usage);
            if !vname.is_empty() {
                b.push(' ');
                b.push_str(&vname);
            }
            if b.len() <= 4 {
                b.push('\t');
            } else {
                b.push_str("\n    \t");
            }
            b.push_str(&usage.replace('\n', "\n    \t"));
            let def = d.default.go_string();
            if def != d.default.zero().go_string() {
                if matches!(d.default, Val::Str(_)) {
                    b.push_str(&format!(" (default {})", quote(&def)));
                } else {
                    b.push_str(&format!(" (default {def})"));
                }
            }
            out.push_str(&b);
            out.push('\n');
        }
        out
    }

    /// Go's default usage: "Usage of NAME:" and the flags.
    pub fn default_usage(&self) -> String {
        let head = if self.name.is_empty() { "Usage:\n".to_string() } else { format!("Usage of {}:\n", self.name) };
        head + &self.defaults()
    }

    fn print_usage(&self) {
        match &self.usage {
            Some(f) => f(self),
            None => {
                let _ = std::io::stderr().write_all(self.default_usage().as_bytes());
            }
        }
    }

    /// The text of the error the last `parse` failed with, as Go's `err.Error()` ("flag provided but not defined: -x",
    /// "flag: help requested"): some Go commands print it again after the flag package's own message.
    pub fn error(&self) -> String {
        self.error.borrow().clone()
    }

    fn fail(&self, msg: String) -> Failed {
        *self.error.borrow_mut() = msg.clone();
        eprintln!("{msg}");
        self.print_usage();
        Failed
    }

    /// Go's `fs.Parse(args)`.
    pub fn parse(&mut self, args: &[String]) -> Result<(), Failed> {
        let mut rest: Vec<String> = args.to_vec();
        loop {
            if rest.is_empty() {
                break;
            }
            let s = rest[0].clone();
            if s.len() < 2 || !s.starts_with('-') {
                break;
            }
            let mut minuses = 1;
            if s.as_bytes()[1] == b'-' {
                minuses = 2;
                if s.len() == 2 {
                    rest.remove(0);
                    break;
                }
            }
            let mut name = s[minuses..].to_string();
            if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
                self.args = rest;
                return Err(self.fail(format!("bad flag syntax: {s}")));
            }
            rest.remove(0);
            let mut value = None;
            if let Some(i) = name[1..].find('=') {
                value = Some(name[i + 2..].to_string());
                name.truncate(i + 1);
            }
            let Some(def) = self.defs.get(&name) else {
                self.args = rest;
                if name == "help" || name == "h" {
                    *self.error.borrow_mut() = "flag: help requested".into();
                    self.print_usage();
                    return Err(Failed);
                }
                return Err(self.fail(format!("flag provided but not defined: -{name}")));
            };
            let new = match &def.value {
                Val::Bool(_) => match value.as_deref().map(parse_bool).unwrap_or(Some(true)) {
                    Some(b) => Val::Bool(b),
                    None => {
                        let v = value.unwrap_or_default();
                        self.args = rest;
                        return Err(self.fail(format!("invalid boolean value {} for -{name}: parse error", quote(&v))));
                    }
                },
                other => {
                    let v = match value {
                        Some(v) => v,
                        None if !rest.is_empty() => rest.remove(0),
                        None => {
                            self.args = rest;
                            return Err(self.fail(format!("flag needs an argument: -{name}")));
                        }
                    };
                    let parsed = match other {
                        Val::Str(_) => Ok(Val::Str(v.clone())),
                        Val::Int(_) => parse_int(&v).map(Val::Int),
                        Val::Duration(_) => crate::gotime::parse_duration(&v).map(Val::Duration).map_err(|_| "parse error"),
                        Val::List(l) => {
                            let mut l = l.clone();
                            l.push(v.clone());
                            Ok(Val::List(l))
                        }
                        Val::Bool(_) => unreachable!(),
                    };
                    match parsed {
                        Ok(p) => p,
                        Err(why) => {
                            self.args = rest;
                            return Err(self.fail(format!("invalid value {} for flag -{name}: {why}", quote(&v))));
                        }
                    }
                }
            };
            self.defs.get_mut(&name).expect("defined").value = new;
            if !self.actual.contains(&name) {
                self.actual.push(name);
            }
        }
        self.args = rest;
        Ok(())
    }
}

/// Go's `UnquoteUsage`: a name in back quotes in the usage is the value's name (and loses its quotes); otherwise the type's.
fn unquote_usage(v: &Val, usage: &str) -> (String, String) {
    if let Some(i) = usage.find('`') {
        if let Some(j) = usage[i + 1..].find('`') {
            let j = i + 1 + j;
            let name = usage[i + 1..j].to_string();
            let u = format!("{}{}{}", &usage[..i], name, &usage[j + 1..]);
            return (name, u);
        }
    }
    (v.type_name().to_string(), usage.to_string())
}

/// Go's `strconv.ParseBool`.
pub fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

/// Go's `strconv.ParseInt(s, 0, 64)` as the flag package reports it: "parse error" or "value out of range".
pub fn parse_int(s: &str) -> Result<i64, &'static str> {
    let (neg, body) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if body.is_empty() {
        return Err("parse error");
    }
    let lower = body.to_ascii_lowercase();
    // Go looks for a prefix only from three characters on ("0x" alone is octal "x", which fails)
    let (base, digits) = if body.len() >= 3 && lower.starts_with("0x") {
        (16, &body[2..])
    } else if body.len() >= 3 && lower.starts_with("0b") {
        (2, &body[2..])
    } else if body.len() >= 3 && lower.starts_with("0o") {
        (8, &body[2..])
    } else if body.len() > 1 && body.starts_with('0') {
        (8, &body[1..])
    } else {
        (10, body)
    };
    // underscores only with base 0, only between digits (or after the prefix), as Go's underscoreOK
    if body.contains('_') && !underscore_ok(body) {
        return Err("parse error");
    }
    let mut v: u64 = 0;
    let mut any = false;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let d = match c.to_digit(base) {
            Some(d) => d as u64,
            None => return Err("parse error"),
        };
        any = true;
        match v.checked_mul(base as u64).and_then(|x| x.checked_add(d)) {
            Some(x) => v = x,
            // Go stops at the first digit that overflows
            None => return Err("value out of range"),
        }
    }
    if !any {
        return Err("parse error");
    }
    if neg {
        if v > 1u64 << 63 {
            return Err("value out of range");
        }
        Ok((v as i64).wrapping_neg())
    } else {
        if v > i64::MAX as u64 {
            return Err("value out of range");
        }
        Ok(v as i64)
    }
}

/// Go's `underscoreOK`: underscores only between digits or between a base prefix and a digit.
fn underscore_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' {
        let c = b[1] | 0x20;
        if c == b'x' || c == b'b' || c == b'o' {
            hex = c == b'x';
            i = 2;
            saw = b'0';
        }
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && (c | 0x20).is_ascii_hexdigit()) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> FlagSet {
        let mut fs = FlagSet::new("scan-files");
        fs.string("state", "", "remember scanned files here (skips unchanged ones next time)");
        fs.int("max-mb", 200, "skip files larger than this many MB (0 = no limit)");
        fs.list("exclude", "a folder, file or glob that is never scanned (repeatable)");
        fs.bool("json", false, "print JSON");
        fs.duration("for", 0, "how long (at most 4h)");
        fs.string("config", "/etc/heimdall/config.json", "config file");
        fs
    }
    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn spellings_go_accepts() {
        let mut fs = set();
        fs.parse(&v(&["--state", "s", "-max-mb=5", "-exclude", "a", "--exclude=b", "-json", "--for", "1h30m", "x", "-y"])).unwrap();
        assert_eq!(fs.get_str("state"), "s");
        assert_eq!(fs.get_int("max-mb"), 5);
        assert_eq!(fs.get_list("exclude"), v(&["a", "b"]));
        assert!(fs.get_bool("json"));
        assert_eq!(fs.get_duration("for"), 5_400_000_000_000);
        assert_eq!(fs.args(), &v(&["x", "-y"])[..]);
        let mut fs = set();
        fs.parse(&v(&["-json=false", "--", "-state"])).unwrap();
        assert!(!fs.get_bool("json"));
        assert_eq!(fs.args(), &v(&["-state"])[..]);
        assert!(fs.is_set("json") && !fs.is_set("state"));
    }

    #[test]
    fn errors_as_go() {
        for (args, ok) in [(&["-nope"][..], false), (&["-max-mb", "x"], false), (&["-state"], false), (&["---x"], false), (&["-"], true)] {
            let mut fs = set();
            assert_eq!(fs.parse(&v(args)).is_ok(), ok, "{args:?}");
        }
        assert_eq!(parse_int("0x10"), Ok(16));
        assert_eq!(parse_int("010"), Ok(8));
        assert_eq!(parse_int("1_000"), Ok(1000));
        assert_eq!(parse_int("1__0"), Err("parse error"));
        assert_eq!(parse_int("99999999999999999999"), Err("value out of range"));
        assert_eq!(parse_int("-9223372036854775808"), Ok(i64::MIN));
        assert_eq!(parse_int("9223372036854775808"), Err("value out of range"));
    }

    #[test]
    fn defaults_as_go_prints_them() {
        // from Go: flag.NewFlagSet("scan-files", ...) with these flags, fs.PrintDefaults()
        assert_eq!(
            set().defaults(),
            "  -config string\n    \tconfig file (default \"/etc/heimdall/config.json\")\n  -exclude value\n    \ta folder, file or glob that is never scanned (repeatable)\n  -for duration\n    \thow long (at most 4h)\n  -json\n    \tprint JSON\n  -max-mb int\n    \tskip files larger than this many MB (0 = no limit) (default 200)\n  -state string\n    \tremember scanned files here (skips unchanged ones next time)\n"
        );
    }
}
