//! The Wi-Fi helpers' parsers and the Python behaviour layer, against Python itself: made-up input (pieces of what nmcli,
//! ip, ss, heimdalld origin, WireGuard files, JSON files and web servers write, mixed with characters that trip parsers:
//! escapes, Unicode spaces and line breaks, digits of other scripts, dotted and dotless i, controls) goes to the shipped
//! Python programs' own functions and Python's json, re, ipaddress, http.client and urllib (one process,
//! rust/parity/harness/wifitools-oracle.py) and to the port; the answers, written as Python's json.dumps writes them, must
//! be the same text. Seeded, so a failure repeats.

use heimdall::cli::wifitools::{addr, check, guard, net, py};
use py::{Dict, Val};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a, T: ?Sized>(&mut self, xs: &[&'a T]) -> &'a T {
        xs[self.below(xs.len())]
    }
    fn chance(&mut self, pct: usize) -> bool {
        self.below(100) < pct
    }
    /// A character parsers trip over, or an ordinary one.
    fn ch(&mut self) -> char {
        const ODD: &[char] = &[
            ':',
            '\\',
            '\r',
            '\n',
            '\t',
            ' ',
            '\u{b}',
            '\u{c}',
            '\u{1c}',
            '\u{1d}',
            '\u{1f}',
            '\u{85}',
            '\u{a0}',
            '\u{2028}',
            '\u{2029}',
            '\u{2003}',
            '\u{3000}',
            '\u{200b}',
            '\u{feff}',
            '\u{e9}',
            '\u{1f600}',
            '\u{661}',
            '\u{ff11}',
            '\u{130}',
            '\u{131}',
            '\u{17f}',
            '\u{212a}',
            '\u{0}',
            '\u{7f}',
            '_',
            '-',
            '.',
            '%',
            '#',
            '?',
            '/',
            '[',
            ']',
            '"',
            '\'',
            '{',
            '}',
            ',',
            '=',
            ';',
            'A',
            'S',
        ];
        match self.below(10) {
            0..=4 => (b' ' + self.below(95) as u8) as char,
            5..=7 => ODD[self.below(ODD.len())],
            8 => char::from_u32(0x80 + self.below(0xd000) as u32).unwrap_or('x'),
            _ => char::from_u32(0x10000 + self.below(0x20000) as u32).unwrap_or('y'),
        }
    }
    fn junk(&mut self, max: usize) -> String {
        let n = self.below(max + 1);
        (0..n).map(|_| self.ch()).collect()
    }
    /// Pieces joined, each sometimes replaced by junk.
    fn compose(&mut self, pieces: &[&str], n: usize) -> String {
        let k = self.below(n + 1);
        (0..k).map(|_| if self.chance(20) { self.junk(4) } else { self.pick(pieces).to_string() }).collect()
    }
}

/// A question to the oracle: the function and its arguments (already JSON).
struct Q {
    f: &'static str,
    args: Vec<String>,
}

fn s(x: &str) -> String {
    py::dumps(&Val::Str(x.to_string()), None)
}

fn hex(b: &[u8]) -> String {
    format!("{{\"hex\": \"{}\"}}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

/// Python's answers, one line each, as it wrote them.
fn oracle(qs: &[Q]) -> Option<Vec<String>> {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/harness/wifitools-oracle.py");
    let mut child = match Command::new("python3").arg("-I").arg(&script).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("skipped: no python3");
            return None;
        }
    };
    let mut input = String::new();
    for q in qs {
        input.push_str(&format!("{{\"f\": \"{}\", \"a\": [{}]}}\n", q.f, q.args.join(", ")));
    }
    let mut w = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = w.write_all(input.as_bytes());
    });
    let out: Vec<String> = BufReader::new(child.stdout.take().unwrap()).lines().map(|l| l.unwrap()).collect();
    writer.join().unwrap();
    assert!(child.wait().unwrap().success(), "the oracle failed");
    Some(out)
}

fn ok(v: Val) -> String {
    let mut d = Dict::new();
    d.set("ok", v);
    py::dumps(&Val::Dict(d), None)
}

fn err(class: &str) -> String {
    format!("{{\"err\": \"{class}\"}}")
}

fn strs(v: Vec<String>) -> Val {
    Val::List(v.into_iter().map(Val::Str).collect())
}

fn opt(v: Option<String>) -> Val {
    v.map_or(Val::None, Val::Str)
}

fn res(r: py::PyResult<Val>) -> String {
    match r {
        Ok(v) => ok(v),
        Err(e) => err(e.kind),
    }
}

fn fake_resolve(h: &str, port: &str) -> py::PyResult<Vec<String>> {
    addr::idna(h)?;
    let _ = port;
    if h == "vpn.example" {
        Ok(vec!["2001:db8::7".into(), "203.0.113.7".into()])
    } else {
        Err(py::PyErr::new("gaierror", "Name or service not known"))
    }
}

/// The port's answer to a question.
fn port(q: &Q, raw: &[Vec<u8>]) -> String {
    let a = |i: usize| -> String {
        match py::loads(&q.args[i]).unwrap() {
            Val::Str(x) => x,
            _ => panic!("not a string"),
        }
    };
    match q.f {
        "split_nmcli" => ok(strs(check::split_nmcli(&a(0)))),
        "wifi_networks" => ok(Val::List(
            check::wifi_networks(&a(0))
                .into_iter()
                .map(|n| {
                    let mut d = Dict::new();
                    d.set("active", Val::Bool(n.active));
                    d.set("ssid", Val::Str(n.ssid));
                    d.set("bssid", Val::Str(n.bssid));
                    d.set("security", Val::Str(n.security));
                    Val::Dict(d)
                })
                .collect(),
        )),
        "security_class" => ok(py::s(check::security_class(&a(0)))),
        "as_number" => ok(opt(check::as_number(&a(0)))),
        "listening_services" => ok(strs(check::listening_services(&a(0)))),
        "origins" => {
            let mut d = Dict::new();
            for (k, (asn, desc)) in check::parse_origins(&a(0)) {
                d.set(&k, strs(vec![asn, desc]));
            }
            ok(Val::Dict(d))
        }
        "guard_split" => ok(strs(guard::split_unescaped_colons(&a(0)))),
        "endpoint" => ok(opt(guard::endpoint_value(&a(0)).map(str::to_string))),
        "parse_wg" => res(guard::parse_wg_with(&a(0), &fake_resolve).map(Val::List)),
        "ruleset" => res(guard::ruleset(&py::loads(&q.args[0]).unwrap()).map(Val::Str)),
        "mac_is_real" => ok(Val::Bool(guard::mac_is_real(&a(0)))),
        "ip_address" => res(addr::ip_address(&py::loads(&q.args[0]).unwrap())
            .map(|ip| Val::List(vec![Val::Int(ip.version().to_string()), Val::Str(ip.to_string())]))),
        "is_private" => match addr::parse_v4(&a(0)) {
            Some(v) => ok(Val::Bool(addr::v4_is_private(v))),
            None => err("ValueError"),
        },
        "is_loopback" => ok(addr::is_loopback(&a(0)).map_or(Val::None, Val::Bool)),
        "json" => match py::loads(&a(0)) {
            Ok(v) => ok(Val::List(vec![
                py::s(&py::dumps(&v, None)),
                py::s(&py::dumps(&v, Some(1))),
                py::s(&py::dumps(&v, Some(2))),
                py::s(&py::repr(&v)),
                py::s(&py::str_of(&v)),
                Val::Bool(v.truthy()),
            ])),
            Err(py::JsonErr::Value) => err("JSONDecodeError"),
            Err(py::JsonErr::Recursion) => err("RecursionError"),
        },
        "float_repr" => {
            let b: [u8; 8] = raw[0].clone().try_into().unwrap();
            ok(py::s(&py::float_repr(f64::from_le_bytes(b))))
        }
        "int" => res(py::int_str(&a(0)).map(Val::Str)),
        "text" => res(py::text(raw[0].clone()).map(Val::Str)),
        "lines" => {
            let t = a(0);
            ok(Val::List(vec![
                strs(py::splitlines(&t).into_iter().map(str::to_string).collect()),
                py::s(py::strip(&t)),
                strs(py::split_ws(&t).into_iter().map(str::to_string).collect()),
                py::s(&py::printable_prefix(&t, 64)),
            ]))
        }
        "redirect" => match net::redirect_target(&a(0), &a(1)) {
            Some(u) => ok(Val::Str(u)),
            None => err("any"),
        },
        "http" => match net::response_view(&raw[0]) {
            Some((status, loc, body, okr)) => ok(Val::List(vec![
                Val::Int(status.to_string()),
                opt(loc),
                body.map_or(Val::None, |b| Val::Str(b.iter().map(|x| format!("{x:02x}")).collect())),
                Val::Bool(okr),
            ])),
            None => err("any"),
        },
        f => panic!("{f}"),
    }
}

fn questions(rng: &mut Rng) -> (Vec<Q>, Vec<Vec<Vec<u8>>>) {
    let mut qs = Vec::new();
    let mut raws = Vec::new();
    let mut push = |f: &'static str, args: Vec<String>, raw: Vec<Vec<u8>>| {
        qs.push(Q { f, args });
        raws.push(raw);
    };
    let nm = [
        "yes",
        "no",
        ":",
        "\\:",
        "\\\\",
        "\\",
        "Cafe",
        "WPA2",
        "WPA1 WPA2",
        "WEP",
        "--",
        "",
        "00\\:00\\:5e\\:00\\:53\\:01",
        "\n",
        "\r\n",
        " ",
        "\u{2003}",
        "wep",
        "\u{df}",
    ];
    let ss = [
        "tcp",
        "udp",
        " ",
        "LISTEN",
        "UNCONN",
        "0",
        "0.0.0.0",
        "127.0.0.1",
        "[::]",
        "[::1]",
        "*",
        ":",
        "22",
        "68",
        "5353",
        "1900",
        "%wlan0",
        "[fe80::1",
        "]",
        "::ffff:127.0.0.2",
        "\n",
        "192.0.2.10",
        "eth0",
    ];
    let org = [
        "192.0.2.1",
        "  ",
        " ",
        "AS",
        "AS15169",
        "XAS1",
        "1",
        "\u{661}",
        "\u{ff11}",
        "_",
        "(",
        ")",
        "US, ",
        "Google",
        "\n",
        "é",
        "AS9x",
        "unknown",
    ];
    let wg = [
        "Endpoint",
        "endpoint",
        "ENDPO\u{130}NT",
        "Endpo\u{131}nt",
        " = ",
        "=",
        " ",
        "\t",
        "\u{2003}",
        "203.0.113.5",
        "[2001:db8::5]",
        "2001:db8::5",
        "vpn.example",
        "nowhere.test",
        ":51820",
        ":",
        "0300.0.2.1",
        ":0",
        ":+5",
        ":5_1",
        ":\u{661}",
        ":x",
        "\n",
        "#",
        "[Peer]",
        "a..b",
        "::ffff:203.0.113.5",
        "fe80::1%wg0",
    ];
    let ipv = [
        "1", "0", "255", "256", "01", ".", ":", "::", "ffff", "1.2.3.4", "%", "%x", "a", "G", "[", "]", "/", " ", "12345", "0.0.0.0",
        "\u{661}",
    ];
    let urlp = [
        "http:",
        "https:",
        "ftp:",
        "javascript:",
        "//",
        "/",
        "portal.example",
        "[2001:db8::1]",
        ":8080",
        "?",
        "#",
        "a",
        "..",
        ".",
        "%41",
        " ",
        "\u{e9}",
        "\u{ff}",
        "\t",
        "\r\n",
        "x y",
        "@",
        "HTTP:",
        ";p",
    ];
    for _ in 0..1500 {
        let line = rng.compose(&nm, 9);
        push("split_nmcli", vec![s(&line)], vec![]);
        push("guard_split", vec![s(&line)], vec![]);
        push("security_class", vec![s(&rng.compose(&nm, 3))], vec![]);
        push("mac_is_real", vec![s(&rng.compose(&["permanent", "preserve", "--", " ", "\n", "random", "\u{2003}"], 3))], vec![]);
        let out =
            (0..rng.below(5)).map(|_| rng.compose(&nm, 9)).collect::<Vec<_>>().join(rng.pick(&["\n", "\r\n", "\r", "\u{2028}", "\u{85}"]));
        push("wifi_networks", vec![s(&out)], vec![]);
        let o = rng.compose(&org, 8);
        push("as_number", vec![s(&o)], vec![]);
        let oo = (0..rng.below(4)).map(|_| rng.compose(&org, 8)).collect::<Vec<_>>().join("\n");
        push("origins", vec![s(&oo)], vec![]);
        let so = (0..rng.below(4)).map(|_| rng.compose(&ss, 12)).collect::<Vec<_>>().join("\n");
        push("listening_services", vec![s(&so)], vec![]);
        let w = rng.compose(&wg, 8);
        push("endpoint", vec![s(&w)], vec![]);
        let wf = (0..rng.below(4)).map(|_| rng.compose(&wg, 6)).collect::<Vec<_>>().join("\n");
        let wf: String = wf.chars().filter(|c| c.is_ascii()).collect(); // names that are not ASCII go through IDNA 2003 in Python (not carried over)
        push("parse_wg", vec![s(&wf)], vec![]);
        let ip = rng.compose(&ipv, 10);
        push("ip_address", vec![s(&ip)], vec![]);
        push("is_loopback", vec![s(&ip)], vec![]);
        let v4 = format!("{}.{}.{}.{}", rng.below(256), rng.below(256), rng.below(256), rng.below(256));
        push("is_private", vec![s(&v4)], vec![]);
        let n = rng.next();
        let (n64, n32) = (n.to_string(), (n as u32).to_string());
        let choices: [&str; 9] = [&n64, &n32, "-1", "true", "false", "1.5", "null", "[]", "340282366920938463463374607431768211456"];
        push("ip_address", vec![choices[rng.below(choices.len())].to_string()], vec![]);
        let t = rng.compose(&["+", "-", " ", "_", "1", "0", "9", "\u{661}", "\u{ff11}", "\u{2003}", "x", "\u{b2}", "\n"], 8);
        push("int", vec![s(&t)], vec![]);
        push("lines", vec![s(&rng.junk(24))], vec![]);
        let bits = rng.next().to_le_bytes();
        let special =
            [0u64, 1, 0x8000_0000_0000_0000, 0x7ff0_0000_0000_0000, 0x3ff0_0000_0000_0000, 0x4340_0000_0000_0000, 0x3f1a_36e2_eb1c_432d];
        let b = if rng.chance(20) { special[rng.below(special.len())].to_le_bytes() } else { bits };
        push("float_repr", vec![hex(&b)], vec![b.to_vec()]);
        let mut tb: Vec<u8> = rng.junk(10).into_bytes();
        if rng.chance(50) {
            let i = rng.below(tb.len() + 1);
            tb.insert(
                i,
                rng.pick(&[&[0xffu8][..], &[0xc3], &[0xe2, 0x80], &[0xed, 0xa0, 0x80], &[0xf4, 0x90, 0x80, 0x80], &[0xc0, 0x80]]).to_vec()
                    [0],
            );
        }
        push("text", vec![hex(&tb)], vec![tb.clone()]);
        let base = rng
            .pick(&["http://detectportal.firefox.com/success.txt", "http://h/a/b/c?q", "https://[2001:db8::1]:8443/x/", "http://h"])
            .to_string();
        let loc: String = rng.compose(&urlp, 6).chars().filter(|c| (*c as u32) < 0x100).collect();
        push("redirect", vec![s(&base), s(&loc)], vec![]);
    }
    (qs, raws)
}

fn json_texts(rng: &mut Rng, n: usize) -> Vec<String> {
    fn value(rng: &mut Rng, depth: usize) -> String {
        let ws = |rng: &mut Rng| rng.pick(&["", " ", "\n", "\t", "\r\n", "  "]).to_string();
        match rng.below(if depth > 3 { 8 } else { 10 }) {
            0 => "null".into(),
            1 => rng.pick(&["true", "false", "NaN", "Infinity", "-Infinity"]).into(),
            2 => rng
                .pick(&[
                    "0",
                    "-0",
                    "1",
                    "-12",
                    "12345678901234567890123",
                    "1.5",
                    "-0.0",
                    "1e400",
                    "2.5E-3",
                    "1e16",
                    "1e15",
                    "123.456e7",
                    "0.0001",
                    "1E-5",
                    "5e-324",
                    "1.7976931348623157e308",
                ])
                .into(),
            3 => f64::from_bits(rng.next()).to_string().replace("inf", "1e999").replace("NaN", "0"),
            4..=7 => {
                let body: String = (0..rng.below(6))
                    .map(|_| match rng.below(6) {
                        0 => rng
                            .pick(&[
                                "\\n",
                                "\\\"",
                                "\\\\",
                                "\\/",
                                "\\t",
                                "\\u00e9",
                                "\\ud83d\\ude00",
                                "\\u0000",
                                "\\u2028",
                                "\\u007f",
                                "\\b",
                                "\\f",
                            ])
                            .to_string(),
                        _ => {
                            let c = rng.ch();
                            if c == '"' || c == '\\' || (c as u32) < 0x20 {
                                "x".into()
                            } else {
                                c.to_string()
                            }
                        }
                    })
                    .collect();
                format!("\"{body}\"")
            }
            8 => {
                let items: Vec<String> = (0..rng.below(4)).map(|_| format!("{}{}{}", ws(rng), value(rng, depth + 1), ws(rng))).collect();
                format!("[{}]", items.join(","))
            }
            _ => {
                let items: Vec<String> = (0..rng.below(4))
                    .map(|_| {
                        format!(
                            "{}\"{}\"{}:{}{}",
                            ws(rng),
                            rng.pick(&["a", "b", "routers", "", "\\u00e9"]),
                            ws(rng),
                            ws(rng),
                            value(rng, depth + 1)
                        )
                    })
                    .collect();
                format!("{{{}}}", items.join(","))
            }
        }
    }
    (0..n)
        .map(|_| {
            let mut t = value(rng, 0);
            if rng.chance(15) {
                let mut c: Vec<char> = t.chars().collect();
                let i = rng.below(c.len() + 1);
                match rng.below(3) {
                    0 if i < c.len() => {
                        c.remove(i);
                    }
                    _ => {
                        let odd = [',', '"', '\\', ']', '}', ':', ' ', '\u{1}', 'x', '\u{feff}'];
                        c.insert(i, odd[rng.below(odd.len())]);
                    }
                }
                t = c.into_iter().collect();
            }
            t
        })
        .collect()
}

fn http_responses(rng: &mut Rng, n: usize) -> Vec<Vec<u8>> {
    let status = [
        "HTTP/1.1 200 OK",
        "HTTP/1.0 200",
        "HTTP/1.1 204 No Content",
        "HTTP/1.1 302 Found",
        "HTTP/1.1 301",
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK",
        "HTTP/2 200",
        "ICY 200 OK",
        "HTTP/1.1 +200 x",
        "HTTP/1.1 2_00 x",
        "HTTP/1.1 99 x",
        "HTTP/1.1 1000 x",
        "HTTP/0.9 200 x",
        "HTTP/1.1 404 Not Found",
        "HTTP/1.1  200  spaced",
        "",
    ];
    let headers = [
        "Content-Length: 8",
        "Content-Length: 3",
        "Content-Length:  20 ",
        "Content-Length: -1",
        "Content-Length: x",
        "Content-Length: 1_0",
        "content-length: +4",
        "Transfer-Encoding: chunked",
        "transfer-encoding: CHUNKED",
        "Transfer-Encoding: gzip, chunked",
        "Location: http://portal.example/x",
        "location: /a b",
        "Location:\t//h/p",
        "URI: /u",
        "Location: first",
        " folded continuation",
        "\tfolded",
        "Bad Header: x",
        "From someone",
        "X: y",
        ":empty name",
        "Connection: close",
    ];
    let bodies = [
        "success\n",
        "",
        "3\r\nsuc\r\n5\r\ncess\n\r\n0\r\n\r\n",
        "8;ext\r\nsuccess\n\r\n0\r\nT: x\r\n\r\n",
        "0x8\r\nsuccess\n\r\n0\r\n\r\n",
        " 8 \r\nsuccess\n\r\n0\r\n\r\n",
        "z\r\n",
        "-1\r\nabc",
        "4\r\nsu",
        "8\r\nsuccess\nXX0\r\n\r\n",
    ];
    (0..n)
        .map(|_| {
            let mut t = String::new();
            t.push_str(rng.pick(&status));
            t.push_str(rng.pick(&["\r\n", "\n"]));
            for _ in 0..rng.below(5) {
                t.push_str(rng.pick(&headers));
                t.push_str(rng.pick(&["\r\n", "\n"]));
            }
            if !rng.chance(10) {
                t.push_str("\r\n");
            }
            t.push_str(rng.pick(&bodies));
            let mut b: Vec<u8> = t.into_bytes();
            if rng.chance(15) {
                let i = rng.below(b.len() + 1);
                b.insert(i, rng.pick(&[&b'\r', &b'\n', &b':', &0xe9u8, &b' ', &b'0']).to_owned());
            }
            b
        })
        .collect()
}

/// Whether a JSON text holds a \u escape of half a surrogate pair: Python keeps such a string, a Rust string cannot hold
/// it, so the port reads the file as damaged (docs/RUST_CLI.md; neither program writes one).
fn lone_surrogate(t: &str) -> bool {
    let c: Vec<char> = t.chars().collect();
    let hex4 = |i: usize| -> Option<u32> {
        (i + 4 <= c.len()).then(|| c[i..i + 4].iter().collect::<String>()).and_then(|h| u32::from_str_radix(&h, 16).ok())
    };
    let mut i = 0;
    while i + 1 < c.len() {
        if c[i] != '\\' {
            i += 1;
            continue;
        }
        if c[i + 1] == 'u' {
            if let Some(v) = hex4(i + 2) {
                if (0xd800..0xdc00).contains(&v)
                    && c.get(i + 6) == Some(&'\\')
                    && c.get(i + 7) == Some(&'u')
                    && hex4(i + 8).is_some_and(|w| (0xdc00..0xe000).contains(&w))
                {
                    i += 12;
                    continue;
                }
                if (0xd800..0xe000).contains(&v) {
                    return true;
                }
            }
        }
        i += 2;
    }
    false
}

#[test]
fn the_parsers_answer_as_python_does() {
    // another seed: HEIMDALL_PROP_SEED=N (to look further than the fixed one)
    let seed = std::env::var("HEIMDALL_PROP_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed_1234_abcd_0001u64);
    let mut rng = Rng(seed | 1);
    let (mut qs, mut raws) = questions(&mut rng);
    for t in json_texts(&mut rng, 4000).into_iter().filter(|t| !lone_surrogate(t)) {
        qs.push(Q { f: "json", args: vec![s(&t)] });
        raws.push(vec![]);
    }
    for b in http_responses(&mut rng, 3000) {
        qs.push(Q { f: "http", args: vec![hex(&b)] });
        raws.push(vec![b]);
    }
    for _ in 0..1500 {
        let ep = |rng: &mut Rng| -> String {
            let ip = rng.pick(&[
                "\"203.0.113.5\"",
                "\"2001:DB8::5\"",
                "\"::ffff:203.0.113.5\"",
                "\"fe80::1%wg0\"",
                "\"203.0.113.05\"",
                "3405803781",
                "true",
                "1.5",
                "null",
                "[1]",
                "\"x\"",
            ]);
            let port = rng.pick(&[
                "51820",
                "\"51820\"",
                "\" 5_1 \"",
                "2.9",
                "-1",
                "true",
                "\"x\"",
                "null",
                "1e400",
                "NaN",
                "123456789012345678901234567890",
            ]);
            match rng.below(6) {
                0 => format!("{{\"ip\": {ip}}}"),
                1 => format!("{{\"port\": {port}}}"),
                2 => ip.to_string(),
                _ => format!("{{\"ip\": {ip}, \"port\": {port}}}"),
            }
        };
        let eps: Vec<String> = (0..rng.below(4)).map(|_| ep(&mut rng)).collect();
        let iface = rng.pick(&[
            "",
            ", \"iface\": \"wg-heimdall\"",
            ", \"iface\": \"wg0; drop\"",
            ", \"iface\": 7",
            ", \"iface\": null",
            ", \"iface\": \"\u{e9}\"",
        ]);
        let vpn = match rng.below(8) {
            0 => format!("{{\"endpoints\": {{\"a\": 1}}{iface}}}"),
            1 => "\"yes\"".to_string(),
            2 => format!("{{\"endpoints\": \"ab\"{iface}}}"),
            _ => format!("{{\"endpoints\": [{}]{iface}}}", eps.join(", ")),
        };
        qs.push(Q { f: "ruleset", args: vec![vpn] });
        raws.push(vec![]);
    }
    let Some(answers) = oracle(&qs) else { return };
    assert_eq!(answers.len(), qs.len(), "the oracle answered every question");
    let mut bad = Vec::new();
    for ((q, raw), python) in qs.iter().zip(&raws).zip(&answers) {
        let rust = port(q, raw);
        let same = rust == *python
            || (rust.starts_with("{\"err\"") && python.starts_with("{\"err\"") && (rust.contains("\"any\"") || matches!(q.f, "json")));
        if !same {
            bad.push(format!("{}({})\n  Python: {python}\n  Rust:   {rust}", q.f, q.args.join(", ")));
        }
    }
    let total = qs.len();
    eprintln!("{total} cases against Python, {} different", bad.len());
    assert!(
        bad.is_empty(),
        "{} of {total} differ; the first ones:\n{}",
        bad.len(),
        bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n")
    );
}
