//! Sound files cleaned by our own code: MP3 (ID3v2, ID3v1, APE and Lyrics3 tags), FLAC (Vorbis comments, pictures,
//! application data, cue sheets) and WAV (INFO, broadcast extension, iXML, ID3, XMP chunks). The sound itself is copied
//! byte for byte.

use super::{note, Removed};

fn id3_size(b: &[u8]) -> usize {
    b.iter().take(4).fold(0usize, |a, &x| (a << 7) | (x & 0x7F) as usize)
}

/// The kinds of ID3v2 frames in a tag, in plain words.
fn id3_frames(tag: &[u8], r: &mut Removed) {
    let ver = tag[3];
    let mut i = 10;
    let mut kinds: Vec<&str> = vec![];
    while i + 10 <= tag.len() && kinds.len() < 64 {
        let (id, size, hdr): (&[u8], usize, usize) = if ver == 2 {
            let s = ((tag[i + 3] as usize) << 16) | ((tag[i + 4] as usize) << 8) | tag[i + 5] as usize;
            (&tag[i..i + 3], s, 6)
        } else {
            let raw = &tag[i + 4..i + 8];
            let s = if ver == 4 { id3_size(raw) } else { u32::from_be_bytes(raw.try_into().unwrap()) as usize };
            (&tag[i..i + 4], s, 10)
        };
        if id.iter().all(|&b| b == 0) || size == 0 && id[0] == 0 {
            break;
        }
        let k = match id {
            b"TIT2" | b"TT2" => "title",
            b"TPE1" | b"TP1" | b"TPE2" | b"TCOM" | b"TEXT" => "artist",
            b"TALB" | b"TAL" => "album",
            b"COMM" | b"COM" => "comment",
            b"APIC" | b"PIC" => "cover picture",
            b"TDRC" | b"TYER" | b"TDAT" | b"TIME" | b"TDRL" | b"TDEN" | b"TYE" => "dates",
            b"TENC" | b"TSSE" | b"TEN" | b"TSS" => "encoder",
            b"PRIV" | b"GEOB" | b"UFID" => "private data",
            b"TXXX" | b"WXXX" | b"TXX" => "custom fields",
            b"USLT" | b"SYLT" => "lyrics",
            _ => "other fields",
        };
        if !kinds.contains(&k) {
            kinds.push(k);
        }
        i += hdr + size;
    }
    let list = if kinds.is_empty() { String::new() } else { format!(" ({})", kinds.join(", ")) };
    note(r, &format!("ID3 tags{list}"));
}

pub fn mp3(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let mut start = 0;
    // one or more ID3v2 tags at the start
    while d.len() >= start + 10 && &d[start..start + 3] == b"ID3" {
        let size = id3_size(&d[start + 6..start + 10]) + 10 + if d[start + 5] & 0x10 != 0 { 10 } else { 0 };
        let end = (start + size).min(d.len());
        id3_frames(&d[start..end], r);
        start = end;
    }
    let mut end = d.len();
    if end >= start + 128 && &d[end - 128..end - 125] == b"TAG" {
        note(r, "ID3v1 tag (title, artist, comment)");
        end -= 128;
        if end >= start + 227 && &d[end - 227..end - 223] == b"TAG+" {
            end -= 227;
        }
    }
    // Lyrics3 v2: "LYRICS200" at the end, its size in 6 digits before it
    if end >= start + 15 && &d[end - 9..end] == b"LYRICS200" {
        if let Some(n) = std::str::from_utf8(&d[end - 15..end - 9]).ok().and_then(|s| s.parse::<usize>().ok()) {
            if n + 15 <= end - start {
                note(r, "Lyrics3 tag");
                end -= n + 15;
            }
        }
    }
    // APEv2 (and v1): the 32-byte footer "APETAGEX", its size counts the items and the footer; a header adds 32
    if end >= start + 32 && &d[end - 32..end - 24] == b"APETAGEX" {
        let size = u32::from_le_bytes(d[end - 20..end - 16].try_into().unwrap()) as usize;
        let flags = u32::from_le_bytes(d[end - 12..end - 8].try_into().unwrap());
        let total = size + if flags & 0x8000_0000 != 0 { 32 } else { 0 };
        if total <= end - start && size >= 32 {
            note(r, "APE tag");
            end -= total;
        }
    }
    // an ID3v2 tag appended at the end ("3DI" footer)
    if end >= start + 10 && &d[end - 10..end - 7] == b"3DI" {
        let size = id3_size(&d[end - 4..end]) + 20;
        if size <= end - start {
            id3_frames(&d[end - size..end], r);
            end -= size;
        }
    }
    if start >= end {
        return Err("there is no sound in it".into());
    }
    let sync = d[start] == 0xFF && d.get(start + 1).is_some_and(|b| b & 0xE0 == 0xE0);
    if !sync {
        return Err("not an MP3 (no frame after the tags)".into());
    }
    Ok(d[start..end].to_vec())
}

pub fn flac(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let mut i = 0;
    if d.starts_with(b"ID3") && d.len() >= 10 {
        let size = id3_size(&d[6..10]) + 10;
        id3_frames(&d[..size.min(d.len())], r);
        i = size;
    }
    if d.get(i..i + 4) != Some(b"fLaC") {
        return Err("not a FLAC".into());
    }
    i += 4;
    let mut kept: Vec<&[u8]> = vec![];
    loop {
        let h = d.get(i..i + 4).ok_or("the FLAC's metadata is cut off")?;
        let last = h[0] & 0x80 != 0;
        let ty = h[0] & 0x7F;
        let len = ((h[1] as usize) << 16) | ((h[2] as usize) << 8) | h[3] as usize;
        let block = d.get(i..i + 4 + len).ok_or("a FLAC block runs past the end")?;
        match ty {
            0 | 3 => kept.push(block),
            1 => {}
            2 => note(r, "Application data"),
            4 => {
                // the field names, not their values
                let body = &block[4..];
                let mut names: Vec<String> = vec![];
                let vlen = body.get(..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
                let mut p = 4 + vlen;
                let n = body.get(p..p + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                p += 4;
                for _ in 0..n.min(256) {
                    let Some(l) = body.get(p..p + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize) else { break };
                    let Some(c) = body.get(p + 4..(p + 4).saturating_add(l)) else { break };
                    let name = String::from_utf8_lossy(c.split(|&b| b == b'=').next().unwrap_or(b"")).to_ascii_uppercase();
                    if !name.is_empty() && !names.contains(&name) && names.len() < 12 {
                        names.push(name);
                    }
                    p += 4 + l;
                }
                note(r, &if names.is_empty() { "Tags (Vorbis comments)".to_string() } else { format!("Tags ({})", names.join(", ")) });
            }
            5 => note(r, "Cue sheet (disc catalogue numbers)"),
            6 => note(r, "Cover picture"),
            _ => note(r, "Other metadata"),
        }
        i += 4 + len;
        if last {
            break;
        }
    }
    if kept.first().is_none_or(|b| b[0] & 0x7F != 0) {
        return Err("the FLAC has no stream information first".into());
    }
    let mut out = b"fLaC".to_vec();
    let n = kept.len();
    for (k, b) in kept.into_iter().enumerate() {
        let mut b = b.to_vec();
        b[0] = (b[0] & 0x7F) | if k + 1 == n { 0x80 } else { 0 };
        out.extend(b);
    }
    out.extend_from_slice(&d[i..]);
    Ok(out)
}

pub fn wav(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    if d.len() < 12 || &d[..4] != b"RIFF" || &d[8..12] != b"WAVE" {
        return Err("not a WAV (RF64 and others are not cleaned)".into());
    }
    let end = (u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize).saturating_add(8).min(d.len());
    let mut body = b"WAVE".to_vec();
    let mut i = 12;
    let mut data = false;
    while i + 8 <= end {
        let id = &d[i..i + 4];
        let len = u32::from_le_bytes(d[i + 4..i + 8].try_into().unwrap()) as usize;
        let stop = (i + 8).saturating_add(len).saturating_add(len & 1).min(end);
        let chunk = &d[i..stop];
        match id {
            b"fmt " | b"fact" | b"cue " | b"smpl" | b"inst" => body.extend_from_slice(chunk),
            b"data" => {
                data = true;
                body.extend_from_slice(chunk);
                if chunk.len() % 2 == 1 {
                    body.push(0);
                }
            }
            b"LIST" => match chunk.get(8..12) {
                Some(b"INFO") => note(r, "Tags (INFO: title, artist, software, dates)"),
                Some(b"adtl") => note(r, "Marker labels"),
                _ => note(r, "Other metadata (LIST)"),
            },
            b"bext" => note(r, "Broadcast extension (originator, date and time, history)"),
            b"iXML" => note(r, "iXML recorder data (device, scene, take)"),
            b"id3 " | b"ID3 " => note(r, "ID3 tags"),
            b"_PMX" => note(r, "XMP metadata"),
            b"axml" => note(r, "Broadcast XML (axml)"),
            b"JUNK" | b"junk" | b"PAD " | b"FLLR" => {}
            _ => note(r, &format!("Private data ({})", String::from_utf8_lossy(id).escape_default())),
        }
        i = stop.max(i + 8);
    }
    if !data {
        return Err("the WAV has no sound data".into());
    }
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend(body);
    Ok(out)
}
