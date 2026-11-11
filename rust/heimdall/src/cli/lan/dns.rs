//! The small DNS message codec of the device list (Go: internal/lan/dns.go): enough for multicast DNS discovery. Names are Go
//! strings (any bytes: whoever runs a device chooses its name), so they are kept as bytes until they are cleaned.

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;

/// One answer, authority or additional record.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    pub name: Vec<u8>,
    pub rtype: u16,
    /// PTR target, SRV target
    pub ptr: Vec<u8>,
    /// A (4 bytes), AAAA (16 bytes)
    pub ip: Option<Vec<u8>>,
    pub txt: Vec<Vec<u8>>,
    pub port: u16,
}

/// Why a message did not read, as Go's errors say it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// "short dns message"
    Short,
    /// "not a response"
    NotResponse,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Error::Short => "short dns message",
            Error::NotResponse => "not a response",
        })
    }
}

fn be16(m: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([m[off], m[off + 1]])
}

/// A message asking for each name's PTR records (a standard query: answers go to the group).
pub fn query(names: &[&str]) -> Vec<u8> {
    let mut b = vec![0u8; 12];
    b[4..6].copy_from_slice(&(names.len() as u16).to_be_bytes());
    for n in names {
        for label in n.strip_suffix('.').unwrap_or(n).split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.extend_from_slice(&[0, 0, TYPE_PTR as u8, 0, 1]);
    }
    b
}

/// Decodes a possibly compressed name at `off`: the name and the offset after it.
pub fn read_name(m: &[u8], mut off: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        if off >= m.len() {
            return Err(Error::Short);
        }
        let l = m[off] as usize;
        if l == 0 {
            off += 1;
            let end = end.unwrap_or(off);
            return Ok((labels.join(&b"."[..]), end));
        } else if l & 0xc0 == 0xc0 {
            if off + 1 >= m.len() || jumps > 16 {
                return Err(Error::Short);
            }
            if end.is_none() {
                end = Some(off + 2);
            }
            off = (be16(m, off) & 0x3fff) as usize;
            jumps += 1;
        } else {
            if off + 1 + l > m.len() {
                return Err(Error::Short);
            }
            labels.push(&m[off + 1..off + 1 + l]);
            off += 1 + l;
        }
    }
}

/// Every answer, authority and additional record of a response (questions skipped). On a cut record, the records read so far
/// and the error (Go returns both).
pub fn parse(m: &[u8]) -> (Vec<Record>, Option<Error>) {
    if m.len() < 12 {
        return (Vec::new(), Some(Error::Short));
    }
    if m[2] & 0x80 == 0 {
        return (Vec::new(), Some(Error::NotResponse));
    }
    let qd = be16(m, 4) as usize;
    let rr = be16(m, 6) as usize + be16(m, 8) as usize + be16(m, 10) as usize;
    let mut off = 12;
    for _ in 0..qd {
        match read_name(m, off) {
            Ok((_, o)) => off = o + 4,
            Err(e) => return (Vec::new(), Some(e)),
        }
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < rr && i < 256 {
        let (name, o) = match read_name(m, off) {
            Ok(x) if x.1 + 10 <= m.len() => x,
            _ => return (out, Some(Error::Short)),
        };
        let mut r = Record { name, rtype: be16(m, o), ..Record::default() };
        let rdlen = be16(m, o + 8) as usize;
        let data = o + 10;
        if data + rdlen > m.len() {
            return (out, Some(Error::Short));
        }
        match r.rtype {
            TYPE_A if rdlen == 4 => r.ip = Some(m[data..data + 4].to_vec()),
            TYPE_AAAA if rdlen == 16 => r.ip = Some(m[data..data + 16].to_vec()),
            TYPE_PTR => r.ptr = read_name(m, data).map(|x| x.0).unwrap_or_default(),
            TYPE_SRV if rdlen >= 7 => {
                r.port = be16(m, data + 4);
                r.ptr = read_name(m, data + 6).map(|x| x.0).unwrap_or_default();
            }
            TYPE_TXT => {
                let mut p = data;
                while p < data + rdlen {
                    let l = m[p] as usize;
                    if p + 1 + l > data + rdlen {
                        break;
                    }
                    r.txt.push(m[p + 1..p + 1 + l].to_vec());
                    p += 1 + l;
                }
            }
            _ => {}
        }
        out.push(r);
        off = data + rdlen;
        i += 1;
    }
    (out, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pointer_loop_ends() {
        let mut m = vec![0u8; 12];
        m[2] = 0x84;
        m[7] = 1;
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse(&m).1, Some(Error::Short));
        assert_eq!(
            query(&["_ipp._tcp.local"])[12..],
            [4, b'_', b'i', b'p', b'p', 4, b'_', b't', b'c', b'p', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 12, 0, 1]
        );
    }
}
