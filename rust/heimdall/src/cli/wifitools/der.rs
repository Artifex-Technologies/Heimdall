//! What the Wi-Fi check needs from a certificate to word a refusal as OpenSSL (Python's `ssl`) words it: the issuer and
//! subject names, the validity and the key identifiers. A small reader of the DER of X.509 (RFC 5280); anything it cannot
//! read is simply not known (`None`), never a panic.

/// One TLV: (tag, contents, the rest after it).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&l0, mut rest) = rest.split_first()?;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut l = 0usize;
        for &x in &rest[..n] {
            l = l << 8 | x as usize;
        }
        rest = &rest[n..];
        l
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// The parts of a certificate the check reads.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Cert {
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    /// seconds since 1970
    pub not_before: i64,
    pub not_after: i64,
    pub subject_key_id: Option<Vec<u8>>,
    pub authority_key_id: Option<Vec<u8>>,
}

fn digits(s: &[u8]) -> Option<i64> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// Days from 1970-01-01 to a civil date.
fn days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) in seconds.
fn time(tag: u8, v: &[u8]) -> Option<i64> {
    let (y, rest) = match tag {
        0x17 if v.len() == 13 => {
            let yy = digits(&v[..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &v[2..])
        }
        0x18 if v.len() == 15 => (digits(&v[..4])?, &v[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let f = |i: usize| digits(&rest[i..i + 2]);
    let (mo, d, h, mi, s) = (f(0)?, f(2)?, f(4)?, f(6)?, f(8)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    Some(days(y, mo, d) * 86400 + h * 3600 + mi * 60 + s)
}

/// Reads a certificate's DER.
pub fn parse(der: &[u8]) -> Option<Cert> {
    let (0x30, cert, _) = tlv(der)? else { return None };
    let (0x30, tbs, _) = tlv(cert)? else { return None };
    let mut rest = tbs;
    let (mut tag, mut v, mut r) = tlv(rest)?;
    if tag == 0xa0 {
        rest = r; // version
        (tag, v, r) = tlv(rest)?;
    }
    let _ = (tag, v); // serial number
    let (_, _, r) = tlv(r)?; // signature algorithm
    let issuer_all = &r[..r.len() - tlv(r)?.2.len()];
    let (_, _, r) = tlv(r)?;
    let (0x30, validity, r) = tlv(r)? else { return None };
    let (t1, v1, vr) = tlv(validity)?;
    let (t2, v2, _) = tlv(vr)?;
    let subject_all = &r[..r.len() - tlv(r)?.2.len()];
    let (_, _, r) = tlv(r)?;
    let (_, _, mut r) = tlv(r)?; // the public key
    let mut c = Cert {
        issuer: issuer_all.to_vec(),
        subject: subject_all.to_vec(),
        not_before: time(t1, v1)?,
        not_after: time(t2, v2)?,
        ..Cert::default()
    };
    while !r.is_empty() {
        let (tag, v, next) = tlv(r)?;
        r = next;
        if tag != 0xa3 {
            continue;
        }
        let (0x30, mut exts, _) = tlv(v)? else { return Some(c) };
        while !exts.is_empty() {
            let (_, ext, next) = tlv(exts)?;
            exts = next;
            let (0x06, oid, er) = tlv(ext)? else { continue };
            let (mut t, mut val, er2) = tlv(er)?;
            if t == 0x01 {
                (t, val, _) = tlv(er2)?; // critical
            }
            if t != 0x04 {
                continue;
            }
            match oid {
                // subjectKeyIdentifier: OCTET STRING
                [0x55, 0x1d, 0x0e] => {
                    if let Some((0x04, id, _)) = tlv(val) {
                        c.subject_key_id = Some(id.to_vec());
                    }
                }
                // authorityKeyIdentifier: SEQUENCE { [0] keyIdentifier ... }
                [0x55, 0x1d, 0x23] => {
                    if let Some((0x30, seq, _)) = tlv(val) {
                        if let Some((0x80, id, _)) = tlv(seq) {
                            c.authority_key_id = Some(id.to_vec());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Some(c)
}

impl Cert {
    /// Whether `issuer` may have issued this certificate, as OpenSSL guesses it while building a chain: the names match and,
    /// where both say, the key identifiers.
    pub fn issued_by(&self, issuer: &Cert) -> bool {
        self.issuer == issuer.subject
            && match (&self.authority_key_id, &issuer.subject_key_id) {
                (Some(a), Some(s)) => a == s,
                _ => true,
            }
    }

    /// Self-signed as OpenSSL decides it (`X509_self_signed` without checking the signature).
    pub fn self_signed(&self) -> bool {
        self.issued_by(self)
    }
}
