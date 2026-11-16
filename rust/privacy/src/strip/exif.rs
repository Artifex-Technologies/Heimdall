//! EXIF (a TIFF structure) read only to say what it holds, and the one tag a cleaned picture keeps: its orientation (without
//! it a phone photo would show on its side). Bounded: at most 8 IFDs of 1000 entries, every offset checked.

/// What an EXIF block holds, in plain words, and the picture's orientation (1 to 8; 1 when not given).
pub fn describe(t: &[u8]) -> (Vec<String>, u16) {
    let mut out: Vec<&str> = vec![];
    let mut orientation = 1;
    let Some(le) = (match t.get(..4) {
        Some(b"II\x2A\0") => Some(true),
        Some(b"MM\0\x2A") => Some(false),
        _ => None,
    }) else {
        return (vec!["EXIF data".into()], 1);
    };
    let u16_at = |i: usize| t.get(i..i + 2).map(|b| if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) });
    let u32_at = |i: usize| {
        t.get(i..i + 4).map(|b| {
            let a = [b[0], b[1], b[2], b[3]];
            if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        })
    };
    // (offset, which IFD: 0 main, 1 thumbnail, 2 exif, 3 gps)
    let mut todo: Vec<(usize, u8)> = vec![(u32_at(4).unwrap_or(0) as usize, 0)];
    let mut seen = vec![];
    while let Some((off, which)) = todo.pop() {
        if off < 8 || off >= t.len() || seen.contains(&off) || seen.len() >= 8 {
            continue;
        }
        seen.push(off);
        let Some(n) = u16_at(off) else { continue };
        if which == 1 {
            out.push("Thumbnail (EXIF)");
        }
        if which == 3 && n > 0 {
            out.push("GPS position (EXIF)");
        }
        for k in 0..(n as usize).min(1000) {
            let e = off + 2 + k * 12;
            let (Some(tag), Some(v)) = (u16_at(e), u32_at(e + 8)) else { break };
            match (which, tag) {
                (0, 0x0112) => orientation = u16_at(e + 8).filter(|o| (1..=8).contains(o)).unwrap_or(1),
                (0, 0x8769) => todo.push((v as usize, 2)),
                (0, 0x8825) => todo.push((v as usize, 3)),
                (0 | 2, 0x010F | 0x0110) => out.push("Camera make and model (EXIF)"),
                (0 | 2, 0x0131 | 0x000B) => out.push("Software (EXIF)"),
                (0 | 2, 0x013B | 0x8298 | 0xA430) => out.push("Author, owner and copyright (EXIF)"),
                (0 | 2, 0x010E | 0x9286 | 0x9C9B..=0x9C9F) => out.push("Description and comments (EXIF)"),
                (0 | 2, 0x0132 | 0x9003 | 0x9004 | 0x9010..=0x9012 | 0x9290..=0x9292) => out.push("Dates and times (EXIF)"),
                (0 | 2, 0x927C) => out.push("Maker notes (EXIF)"),
                (0 | 2, 0xA431 | 0xA433..=0xA435) => out.push("Camera and lens serial numbers (EXIF)"),
                (0 | 2, 0xA420) => out.push("Picture ID (EXIF)"),
                (0 | 2, 0x013C) => out.push("Computer name (EXIF)"),
                (0, 0x0100..=0x0103 | 0x011A | 0x011B | 0x0128 | 0x0213) => {}
                _ => out.push("Camera settings (EXIF)"),
            }
        }
        if which == 0 {
            if let Some(next) = u32_at(off + 2 + n as usize * 12) {
                todo.push((next as usize, 1));
            }
        }
    }
    let mut v: Vec<String> = vec![];
    for s in out {
        if !v.iter().any(|x| x == s) {
            v.push(s.to_string());
        }
    }
    (v, orientation)
}

/// A TIFF block with nothing but the orientation (big-endian): what a cleaned picture keeps when it is turned.
pub fn orientation_only(o: u16) -> Vec<u8> {
    let mut t = b"MM\0\x2A\0\0\0\x08\0\x01".to_vec();
    t.extend_from_slice(&[0x01, 0x12, 0, 3, 0, 0, 0, 1]);
    t.extend_from_slice(&o.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_made_up_camera_is_read() {
        let (what, o) = describe(&crate::samples::exif_tiff());
        assert_eq!(o, 6);
        for w in [
            "GPS position (EXIF)",
            "Camera make and model (EXIF)",
            "Software (EXIF)",
            "Dates and times (EXIF)",
            "Maker notes (EXIF)",
            "Camera and lens serial numbers (EXIF)",
        ] {
            assert!(what.iter().any(|x| x == w), "{w}: {what:?}");
        }
        let (what, o) = describe(&orientation_only(6));
        assert_eq!(o, 6);
        assert!(what.is_empty(), "the orientation alone is nothing hidden: {what:?}");
    }

    #[test]
    fn broken_exif_is_not_a_panic() {
        let t = crate::samples::exif_tiff();
        for cut in 0..t.len() {
            let _ = describe(&t[..cut]);
        }
        // an IFD that points at itself
        let mut l = b"II\x2A\0\x08\0\0\0\x01\0\x69\x87\x04\0\x01\0\0\0\x08\0\0\0\x08\0\0\0".to_vec();
        l.extend_from_slice(&[0; 8]);
        let _ = describe(&l);
    }
}
