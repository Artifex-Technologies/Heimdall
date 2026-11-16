//! Pictures: JPEG, PNG, WebP, HEIF/AVIF and TIFF without EXIF (GPS included), XMP, IPTC, maker notes, comments and
//! thumbnails. What makes the picture look as it does stays: the colour profile, Adobe's colour transform, the orientation.

use super::{exif, Removed};

fn note(r: &mut Removed, s: &str) {
    if !r.iter().any(|x| x == s) {
        r.push(s.to_string());
    }
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    b.get(i..i + 2).map(|x| u16::from_be_bytes([x[0], x[1]]))
}
fn be32(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
}

// ---- JPEG ----

pub fn jpeg(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    if !d.starts_with(b"\xFF\xD8") {
        return Err("not a JPEG".into());
    }
    let mut out = Vec::with_capacity(d.len());
    out.extend_from_slice(b"\xFF\xD8");
    let mut orientation = 1;
    let mut i = 2;
    let mut header_done = false;
    let mut segs: Vec<(u8, &[u8])> = vec![];
    loop {
        // markers may be padded with 0xFF bytes
        while i < d.len() && d[i] == 0xFF && d.get(i + 1) == Some(&0xFF) {
            i += 1;
        }
        if i + 1 >= d.len() || d[i] != 0xFF {
            return Err("the JPEG ends before its picture".into());
        }
        let m = d[i + 1];
        if m == 0xD9 {
            break;
        }
        if (0xD0..=0xD7).contains(&m) || m == 0x01 {
            segs.push((m, &d[i..i + 2]));
            i += 2;
            continue;
        }
        let len = be16(d, i + 2).ok_or("a JPEG segment is cut off")? as usize;
        if len < 2 || i + 2 + len > d.len() {
            return Err("a JPEG segment runs past the end".into());
        }
        let seg = &d[i..i + 2 + len];
        let body = &seg[4..];
        i += 2 + len;
        let keep = match m {
            0xE0 if body.starts_with(b"JFIF\0") => true,
            0xE0 => {
                note(r, "Thumbnail (JFXX)");
                false
            }
            0xE1 if body.starts_with(b"Exif\0") => {
                let (what, o) = exif::describe(body.get(6..).unwrap_or(&[]));
                orientation = o;
                for w in what {
                    note(r, &w);
                }
                false
            }
            0xE1 if body.starts_with(b"http://ns.adobe.com/xap/1.0/\0") || body.starts_with(b"http://ns.adobe.com/xmp/extension/\0") => {
                note(r, "XMP metadata");
                false
            }
            0xE1 => {
                note(r, "Other metadata (APP1)");
                false
            }
            0xE2 if body.starts_with(b"ICC_PROFILE\0") => true,
            0xE2 if body.starts_with(b"MPF\0") => {
                note(r, "Multi-picture index (MPF)");
                false
            }
            0xEE if body.starts_with(b"Adobe") => true,
            0xED => {
                note(r, "Photoshop and IPTC data (captions, places, names)");
                false
            }
            0xE2..=0xEF => {
                note(r, &format!("Maker data (APP{})", m - 0xE0));
                false
            }
            0xFE => {
                note(r, "Comment");
                false
            }
            _ => true,
        };
        if m == 0xDA {
            // the scan: the segment, then entropy-coded data up to the next marker that is not a restart or a stuffed byte
            if !header_done {
                emit_header(&mut out, &segs, orientation);
                header_done = true;
                segs.clear();
            }
            out.extend_from_slice(seg);
            let start = i;
            while i + 1 < d.len() && !(d[i] == 0xFF && d[i + 1] != 0 && !(0xD0..=0xD7).contains(&d[i + 1])) {
                i += 1;
            }
            if i + 1 >= d.len() {
                return Err("the JPEG's picture data has no end".into());
            }
            out.extend_from_slice(&d[start..i]);
            continue;
        }
        if keep {
            if header_done {
                out.extend_from_slice(seg);
            } else {
                segs.push((m, seg));
            }
        }
    }
    if !header_done {
        return Err("the JPEG has no picture data".into());
    }
    out.extend_from_slice(b"\xFF\xD9");
    if i + 2 < d.len() {
        note(r, "Data after the picture (another picture, a preview or a depth map)");
    }
    Ok(out)
}

/// The kept segments before the picture, with the orientation as a tiny EXIF right after JFIF when the picture is turned.
fn emit_header(out: &mut Vec<u8>, segs: &[(u8, &[u8])], orientation: u16) {
    let mut placed = orientation == 1;
    for (m, s) in segs {
        if !placed && *m != 0xE0 {
            let mut body = b"Exif\0\0".to_vec();
            body.extend_from_slice(&exif::orientation_only(orientation));
            out.extend_from_slice(&[0xFF, 0xE1]);
            out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
            out.extend_from_slice(&body);
            placed = true;
        }
        out.extend_from_slice(s);
    }
}

// ---- PNG ----

const PNG_KEEP: &[&[u8; 4]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"bKGD", b"pHYs", b"hIST", b"sPLT", b"acTL",
    b"fcTL", b"fdAT", b"cICP", b"mDCv", b"cLLi",
];

fn png_chunk(ty: &[u8], body: &[u8]) -> Vec<u8> {
    let mut c = (body.len() as u32).to_be_bytes().to_vec();
    c.extend_from_slice(ty);
    c.extend_from_slice(body);
    let mut crc = flate2::Crc::new();
    crc.update(ty);
    crc.update(body);
    c.extend_from_slice(&crc.sum().to_be_bytes());
    c
}

pub fn png(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    if !d.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("not a PNG".into());
    }
    let mut out = d[..8].to_vec();
    let mut i = 8;
    let mut orientation = 1;
    let mut ended = false;
    while i + 12 <= d.len() {
        let len = be32(d, i).unwrap_or(u32::MAX) as usize;
        let ty = &d[i + 4..i + 8];
        if len > d.len() - i - 12 {
            return Err("a PNG chunk runs past the end".into());
        }
        let chunk = &d[i..i + 12 + len];
        let body = &d[i + 8..i + 8 + len];
        i += 12 + len;
        if PNG_KEEP.iter().any(|k| &k[..] == ty) {
            if ty == b"IDAT" && orientation != 1 {
                out.extend(png_chunk(b"eXIf", &exif::orientation_only(orientation)));
                orientation = 1;
            }
            out.extend_from_slice(chunk);
            if ty == b"IEND" {
                ended = true;
                break;
            }
            continue;
        }
        match ty {
            b"tEXt" | b"zTXt" | b"iTXt" if body.starts_with(b"XML:com.adobe.xmp\0") => note(r, "XMP metadata"),
            b"tEXt" | b"zTXt" | b"iTXt" => note(r, "Text fields (author, software, comments)"),
            b"eXIf" => {
                let (what, o) = exif::describe(body);
                orientation = o;
                for w in what {
                    note(r, &w);
                }
            }
            b"tIME" => note(r, "Time it was last changed"),
            _ => note(r, &format!("Private data ({})", String::from_utf8_lossy(ty).escape_default())),
        }
    }
    if !ended {
        return Err("the PNG has no end".into());
    }
    if i < d.len() {
        note(r, "Data after the picture");
    }
    Ok(out)
}

// ---- WebP ----

pub fn webp(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    if d.len() < 12 || &d[..4] != b"RIFF" || &d[8..12] != b"WEBP" {
        return Err("not a WebP".into());
    }
    let end = (u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize).saturating_add(8).min(d.len());
    let mut body = b"WEBP".to_vec();
    let mut i = 12;
    let mut vp8x_at = None;
    let mut orientation = 1;
    while i + 8 <= end {
        let id = &d[i..i + 4];
        let len = u32::from_le_bytes(d[i + 4..i + 8].try_into().unwrap()) as usize;
        let padded = len + (len & 1);
        if len > end - i - 8 {
            return Err("a WebP chunk runs past the end".into());
        }
        let chunk = &d[i..(i + 8 + padded).min(end)];
        let content = &d[i + 8..i + 8 + len];
        i += 8 + padded;
        match id {
            b"VP8X" => {
                if chunk.len() < 18 {
                    return Err("a damaged WebP header".into());
                }
                vp8x_at = Some(body.len());
                body.extend_from_slice(chunk);
            }
            b"VP8 " | b"VP8L" | b"ALPH" | b"ANIM" | b"ANMF" | b"ICCP" => body.extend_from_slice(chunk),
            b"EXIF" => {
                let t = content.strip_prefix(b"Exif\0\0").unwrap_or(content);
                let (what, o) = exif::describe(t);
                orientation = o;
                for w in what {
                    note(r, &w);
                }
            }
            b"XMP " => note(r, "XMP metadata"),
            _ => note(r, &format!("Private data ({})", String::from_utf8_lossy(id).escape_default())),
        }
    }
    if let Some(at) = vp8x_at {
        // the flags byte: 0x08 EXIF, 0x04 XMP
        let keep_exif = orientation != 1;
        body[at + 8] &= !0x04;
        if !keep_exif {
            body[at + 8] &= !0x08;
        } else {
            let t = exif::orientation_only(orientation);
            body.extend_from_slice(b"EXIF");
            body.extend_from_slice(&(t.len() as u32).to_le_bytes());
            body.extend_from_slice(&t);
        }
    }
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend(body);
    Ok(out)
}

// ---- HEIF / AVIF: the Exif and XMP items blanked where they are ----

/// Boxes of a range: (type, content start, end).
fn boxes(d: &[u8], start: usize, end: usize) -> Vec<([u8; 4], usize, usize)> {
    let mut v = vec![];
    let mut i = start;
    while i + 8 <= end && v.len() < 4096 {
        let size = be32(d, i).unwrap_or(0) as u64;
        let ty: [u8; 4] = d[i + 4..i + 8].try_into().unwrap();
        let (hdr, size) = match size {
            0 => (8, (end - i) as u64),
            1 => match d.get(i + 8..i + 16) {
                Some(b) => (16, u64::from_be_bytes(b.try_into().unwrap())),
                None => break,
            },
            s => (8, s),
        };
        if size < hdr as u64 || size > (end - i) as u64 {
            break;
        }
        v.push((ty, i + hdr, i + size as usize));
        i += size as usize;
    }
    v
}

fn read_n(d: &[u8], i: &mut usize, n: u8) -> Option<u64> {
    let n = n as usize;
    if n == 0 {
        return Some(0);
    }
    let b = d.get(*i..*i + n)?;
    *i += n;
    Some(b.iter().fold(0u64, |a, &x| (a << 8) | x as u64))
}

pub fn heif(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let top = boxes(d, 0, d.len());
    let (_, ms, me) = *top.iter().find(|b| &b.0 == b"meta").ok_or("no meta box")?;
    let inner = boxes(d, ms + 4, me);
    // items: id -> what (Exif or XMP)
    let mut targets: Vec<(u32, bool)> = vec![];
    if let Some(&(_, s, e)) = inner.iter().find(|b| &b.0 == b"iinf") {
        let ver = d[s];
        let first = s + 4 + if ver == 0 { 2 } else { 4 };
        for (ty, cs, ce) in boxes(d, first.min(e), e) {
            if &ty != b"infe" || ce < cs + 4 {
                continue;
            }
            let v = d[cs];
            let mut i = cs + 4;
            if v < 2 {
                continue;
            }
            let Some(id) = read_n(d, &mut i, if v == 2 { 2 } else { 4 }) else { continue };
            i += 2;
            let Some(it) = d.get(i..i + 4) else { continue };
            i += 4;
            let name_end = d[i.min(ce)..ce].iter().position(|&b| b == 0).map_or(ce, |p| i + p);
            if it == b"Exif" {
                targets.push((id as u32, true));
            } else if it == b"mime" {
                let ct_start = name_end + 1;
                let ct_end = d[ct_start.min(ce)..ce].iter().position(|&b| b == 0).map_or(ce, |p| ct_start + p);
                let ct = String::from_utf8_lossy(&d[ct_start.min(ct_end)..ct_end]).to_ascii_lowercase();
                if ct.contains("rdf+xml") || ct.contains("xmp") {
                    targets.push((id as u32, false));
                }
            }
        }
    }
    if targets.is_empty() {
        return Ok(d.to_vec());
    }
    let &(_, s, e) = inner.iter().find(|b| &b.0 == b"iloc").ok_or("no item locations")?;
    let ver = d[s];
    let mut i = s + 4;
    let sizes = d.get(i..i + 2).ok_or("short iloc")?;
    let (off_sz, len_sz, base_sz) = (sizes[0] >> 4, sizes[0] & 15, sizes[1] >> 4);
    let idx_sz = if ver >= 1 { sizes[1] & 15 } else { 0 };
    i += 2;
    let count = read_n(d, &mut i, if ver < 2 { 2 } else { 4 }).ok_or("short iloc")?;
    let mut out = d.to_vec();
    for _ in 0..count.min(65_536) {
        let Some(id) = read_n(d, &mut i, if ver < 2 { 2 } else { 4 }) else { break };
        let method = if ver >= 1 { read_n(d, &mut i, 2).unwrap_or(0) & 15 } else { 0 };
        i += 2;
        let base = read_n(d, &mut i, base_sz).unwrap_or(0);
        let extents = read_n(d, &mut i, 2).unwrap_or(0);
        let mut ranges = vec![];
        for _ in 0..extents.min(4096) {
            if idx_sz > 0 {
                read_n(d, &mut i, idx_sz);
            }
            let (Some(off), Some(len)) = (read_n(d, &mut i, off_sz), read_n(d, &mut i, len_sz)) else { break };
            ranges.push((base.saturating_add(off), len));
            if i > e {
                break;
            }
        }
        if i > e {
            return Err("damaged item locations".into());
        }
        let Some(&(_, is_exif)) = targets.iter().find(|t| t.0 as u64 == id) else { continue };
        if method != 0 {
            return Err("its metadata is stored in a way this tool does not change".into());
        }
        // the item's bytes, joined (one extent nearly always)
        let mut payload = vec![];
        for &(off, len) in &ranges {
            let (o, l) = (off as usize, len as usize);
            if o.checked_add(l).is_none_or(|x| x > d.len()) {
                return Err("an item runs past the end".into());
            }
            payload.extend_from_slice(&d[o..o + l]);
        }
        let blank = if is_exif {
            let skip = be32(&payload, 0).unwrap_or(0) as usize;
            let (what, _) = exif::describe(payload.get(4 + skip..).unwrap_or(&[]));
            for w in what {
                note(r, &w);
            }
            let mut b = vec![0, 0, 0, 0];
            b.extend_from_slice(b"MM\0\x2A\0\0\0\x08\0\0\0\0\0\0");
            b
        } else {
            note(r, "XMP metadata");
            br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"/><?xpacket end="w"?>"#.to_vec()
        };
        // written over the old bytes, the rest padded (zeros for EXIF, spaces inside the XMP packet's room)
        let mut fill: Vec<u8> = if blank.len() <= payload.len() { blank } else { vec![] };
        fill.resize(payload.len(), if is_exif { 0 } else { b' ' });
        let mut at = 0;
        for &(off, len) in &ranges {
            out[off as usize..off as usize + len as usize].copy_from_slice(&fill[at..at + len as usize]);
            at += len as usize;
        }
    }
    Ok(out)
}

// ---- TIFF ----

/// The tags of the picture itself (what decoders need), kept; everything else goes.
const TIFF_KEEP: &[u16] = &[
    254, 255, 256, 257, 258, 259, 262, 263, 264, 265, 266, 273, 274, 277, 278, 279, 280, 281, 282, 283, 284, 290, 291, 292, 293, 296, 297,
    301, 317, 318, 319, 320, 322, 323, 324, 325, 332, 333, 334, 338, 339, 340, 341, 347, 529, 530, 531, 532, 34675,
];

fn tiff_name(tag: u16) -> &'static str {
    match tag {
        271 | 272 => "Camera make and model",
        305 => "Software",
        306 => "Date and time",
        315 | 33432 => "Author and copyright",
        316 => "Computer name",
        270 | 269 | 285 => "Description, document and page names",
        34665 => "EXIF data (camera, dates, settings)",
        34853 => "GPS position",
        700 => "XMP metadata",
        33723 => "IPTC data (captions, places, names)",
        34377 => "Photoshop data",
        _ => "Other tags",
    }
}

pub fn tiff(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let le = match d.get(..4) {
        Some(b"II\x2A\0") => true,
        Some(b"MM\0\x2A") => false,
        Some(b"II\x2B\0") | Some(b"MM\0\x2B") => return Err("BigTIFF is not cleaned".into()),
        _ => return Err("not a TIFF".into()),
    };
    let g16 = |i: usize| d.get(i..i + 2).map(|b| if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) });
    let g32 = |i: usize| {
        d.get(i..i + 4).map(|b| {
            let a = [b[0], b[1], b[2], b[3]];
            if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        })
    };
    let p16 = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let p32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let tsize = |ty: u16| match ty {
        1 | 2 | 6 | 7 => 1usize,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 => 8,
        _ => 0,
    };
    let mut out = d[..4].to_vec();
    out.extend_from_slice(&p32(0)); // first IFD: patched
    let mut link_at = 4usize;
    let mut off = g32(4).ok_or("short TIFF")? as usize;
    let mut pages = 0;
    let mut seen = vec![];
    while off != 0 {
        if pages >= 256 || seen.contains(&off) || off + 2 > d.len() {
            break;
        }
        seen.push(off);
        pages += 1;
        let n = g16(off).ok_or("short IFD")? as usize;
        if n == 0 || n > 4096 || off + 2 + n * 12 + 4 > d.len() {
            return Err("a damaged IFD".into());
        }
        // (tag, type, count, the value's bytes)
        let mut kept: Vec<(u16, u16, u32, Vec<u8>)> = vec![];
        for k in 0..n {
            let e = off + 2 + k * 12;
            let (tag, ty, count) = (g16(e).unwrap(), g16(e + 2).unwrap(), g32(e + 4).unwrap());
            if tsize(ty) == 0 {
                // a type no reader knows: its size cannot be told, so it cannot be copied
                note(r, "Unreadable tags");
                continue;
            }
            let size = tsize(ty).checked_mul(count as usize).ok_or("a damaged tag")?;
            let val = if size <= 4 {
                d[e + 8..e + 12].to_vec()
            } else {
                let at = g32(e + 8).unwrap() as usize;
                d.get(at..at.checked_add(size).ok_or("a damaged tag")?).ok_or("a tag's value runs past the end")?.to_vec()
            };
            if tag == 330 {
                return Err("a TIFF with sub-pictures (a camera raw file?) is not cleaned".into());
            }
            if tag == 259 && g16(e + 8) == Some(6) {
                return Err("old-style JPEG in TIFF is not cleaned".into());
            }
            if TIFF_KEEP.contains(&tag) {
                kept.push((tag, ty, count, val));
            } else {
                note(r, tiff_name(tag));
            }
        }
        // the picture's data: strips or tiles, copied and their offsets written anew
        let (offs_tag, counts_tag) = if kept.iter().any(|k| k.0 == 324) { (324u16, 325u16) } else { (273, 279) };
        let read_list = |e: &(u16, u16, u32, Vec<u8>)| -> Vec<u32> {
            let sz = tsize(e.1);
            (0..e.2 as usize)
                .map(|i| {
                    let b = &e.3[i * sz..i * sz + sz];
                    match (sz, le) {
                        (2, true) => u16::from_le_bytes([b[0], b[1]]) as u32,
                        (2, false) => u16::from_be_bytes([b[0], b[1]]) as u32,
                        (4, true) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                        (4, false) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                        _ => 0,
                    }
                })
                .collect()
        };
        let oi = kept.iter().position(|k| k.0 == offs_tag).ok_or("the picture has no data")?;
        let ci = kept.iter().position(|k| k.0 == counts_tag).ok_or("the picture has no data sizes")?;
        if ![3, 4].contains(&kept[oi].1) || ![3, 4].contains(&kept[ci].1) || kept[oi].2 != kept[ci].2 {
            return Err("damaged picture data".into());
        }
        let offs = read_list(&kept[oi]);
        let counts = read_list(&kept[ci]);
        let mut new_offs = vec![];
        for (&o, &c) in offs.iter().zip(&counts) {
            let (o, c) = (o as usize, c as usize);
            let chunk = d.get(o..o.checked_add(c).ok_or("damaged picture data")?).ok_or("picture data runs past the end")?;
            if out.len() % 2 == 1 {
                out.push(0);
            }
            new_offs.push(out.len() as u32);
            out.extend_from_slice(chunk);
            // strips that all point at the same bytes would make a copy many times the file's size
            if out.len() > d.len().saturating_mul(2) + 65_536 {
                return Err("damaged picture data (the same data used again and again)".into());
            }
        }
        let mut nv = vec![];
        for o in &new_offs {
            nv.extend_from_slice(&p32(*o));
        }
        kept[oi] = (offs_tag, 4, new_offs.len() as u32, nv);
        // values longer than 4 bytes go before the IFD
        let mut entries: Vec<(u16, u16, u32, [u8; 4])> = vec![];
        for (tag, ty, count, val) in &kept {
            let field = if val.len() <= 4 {
                let mut f = [0u8; 4];
                f[..val.len()].copy_from_slice(val);
                f
            } else {
                if out.len() % 2 == 1 {
                    out.push(0);
                }
                let at = out.len() as u32;
                out.extend_from_slice(val);
                p32(at)
            };
            entries.push((*tag, *ty, *count, field));
        }
        entries.sort_by_key(|e| e.0);
        if out.len() % 2 == 1 {
            out.push(0);
        }
        let ifd_at = out.len() as u32;
        out[link_at..link_at + 4].copy_from_slice(&p32(ifd_at));
        out.extend_from_slice(&p16(entries.len() as u16));
        for (tag, ty, count, field) in entries {
            out.extend_from_slice(&p16(tag));
            out.extend_from_slice(&p16(ty));
            out.extend_from_slice(&p32(count));
            out.extend_from_slice(&field);
        }
        link_at = out.len();
        out.extend_from_slice(&p32(0));
        off = g32(off + 2 + n * 12).unwrap_or(0) as usize;
    }
    if pages == 0 {
        return Err("the TIFF has no picture".into());
    }
    Ok(out)
}
