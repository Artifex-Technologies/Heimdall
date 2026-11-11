//! The Wi-Fi helpers' fuzz targets (rust/fuzz/fuzz_targets/wifi_*.rs; run on their seeds and on random input by
//! tests/cli_wifi_fuzz.rs): every parser of what the network, NetworkManager, ip, ss, heimdalld origin, a WireGuard file or
//! a web server hands the helpers. Besides not panicking, each checks what must always hold.

use super::addr::{self, Ip};
use super::py::{self, Dict, PyErr, Val};
use super::{check, der, guard, net};

/// NetworkManager's terse lines (network names are chosen by whoever runs the access point): split, read, escaped again
/// and split back the same.
pub fn nmcli(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    for line in py::splitlines(&text) {
        let f = check::split_nmcli(line);
        let esc: Vec<String> = f.iter().map(|x| x.replace('\\', "\\\\").replace(':', "\\:")).collect();
        assert_eq!(check::split_nmcli(&esc.join(":")), f, "escaped as nmcli does, the fields come back");
        assert_eq!(guard::split_unescaped_colons(line).join(":"), line);
    }
    for n in check::wifi_networks(&text) {
        assert!(matches!(check::security_class(&n.security), "open" | "wep" | "secured"));
    }
}

/// JSON as Python's json reads it (ip's answers, the helpers' files): what reads is written back and reads the same.
pub fn json(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(v) = py::loads(text) {
        for indent in [None, Some(1), Some(2)] {
            let d = py::dumps(&v, indent);
            let back = py::loads(&d).expect("what was written reads back");
            assert_eq!(py::dumps(&back, indent), d);
        }
        let _ = (py::repr(&v), py::str_of(&v), v.truthy(), v.iter(), v.py_len());
        let _ = guard::ruleset(&v);
        let _ = addr::ip_address(&v);
    }
}

/// A WireGuard file (nothing looked up) and the lockdown rules made from it: they hold back everything but DHCP and the
/// VPN.
pub fn wireguard(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let resolve = |_: &str, _: &str| -> py::PyResult<Vec<String>> { Err(PyErr::new("gaierror", "nothing is looked up")) };
    if let Ok(eps) = guard::parse_wg_with(&text, &resolve) {
        let mut vpn = Dict::new();
        vpn.set("endpoints", Val::List(eps));
        vpn.set("iface", py::s(&text));
        let rs = guard::ruleset(&Val::Dict(vpn)).expect("endpoints read from a file make rules");
        assert!(rs.contains("policy drop;") && !rs.contains("tcp"));
    }
}

/// Certificates the network sends: read, and an untrusted chain worded as OpenSSL words it.
pub fn cert(data: &[u8]) {
    let mid = data.len() / 2;
    let certs: Vec<der::Cert> = [data, &data[..mid], &data[mid..]].iter().filter_map(|d| der::parse(d)).collect();
    if let Some(c) = certs.first() {
        assert!(!c.subject.is_empty() && !c.issuer.is_empty());
    }
    let w = net::untrusted(&certs);
    assert!(w.starts_with("self-signed") || w == "unable to get local issuer certificate");
}

/// A web server's answer as urllib reads it, and where its redirect leads.
pub fn http(data: &[u8]) {
    if let Some((status, loc, body, _)) = net::response_view(data) {
        assert!((100..=999).contains(&status));
        assert!(body.is_none_or(|b| b.len() <= 4096));
        if let Some(u) = loc.and_then(|l| net::redirect_target("http://detectportal.firefox.com/success.txt", &l)) {
            assert!(!u.chars().any(|c| c == ' ' || c.is_control()), "{u:?}");
        }
    }
    let text = String::from_utf8_lossy(data);
    let _ = net::urljoin("https://[2001:db8::1]:8443/a/b?q#f", &text);
}

/// The local tools' text (ss, heimdalld origin) and the address rules: every address read is written back as it reads.
pub fn tools(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let svc = check::listening_services(&text);
    assert!(svc.windows(2).all(|w| w[0] < w[1]));
    let _ = check::parse_origins(&text);
    if let Some(a) = check::as_number(&text) {
        assert!(a.starts_with("AS") && a.chars().count() > 2);
    }
    for w in py::split_ws(&text) {
        if let Some((v, sc)) = addr::parse_v6(w) {
            assert_eq!(addr::parse_v6(&Ip::V6(v, sc.clone()).to_string()), Some((v, sc)));
        }
        if let Some(v) = addr::parse_v4(w) {
            assert_eq!(Ip::V4(v).to_string(), w);
        }
        let _ = (py::int_str(w), addr::is_loopback(w), guard::endpoint_value(w));
    }
    let _ = py::text(data.to_vec());
}
