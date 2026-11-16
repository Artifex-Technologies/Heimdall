//! Documents: Office (docProps, the template's path, Word's editing-session ids, Excel's folder path), OpenDocument (meta.xml,
//! the printer), ZIP archives (comments, extra fields, times, owners), PDF (the document information, XMP, the document id).
//! A ZIP-based file is written anew: unchanged parts are copied as they are compressed, changed parts deflated again, every
//! entry with the same fixed time and no extra fields.

use super::{note, Removed};
use crate::markup;
use crate::pdf;
use crate::zip;

/// The most a cleaned ZIP-based file may unpack to in memory (only the parts that change are unpacked).
const PART: u64 = 64 << 20;

fn has_tag(x: &[u8], local: &str) -> bool {
    markup::tags(x, 100_000).iter().any(|t| t.local() == local)
}

/// Removes every element with this name (an empty one, or from its start tag to its end tag).
pub fn remove_elements(x: &[u8], name: &str) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(x.len());
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut i = 0;
    let mut removed = false;
    while let Some(p) = pdf::find(x, i, open.as_bytes()) {
        // the next byte must end the name
        if !matches!(x.get(p + open.len()), Some(b' ' | b'/' | b'>' | b'\t' | b'\n' | b'\r')) {
            out.extend_from_slice(&x[i..p + open.len()]);
            i = p + open.len();
            continue;
        }
        out.extend_from_slice(&x[i..p]);
        let Some(gt) = x[p..].iter().position(|&b| b == b'>').map(|g| p + g) else {
            i = x.len();
            removed = true;
            break;
        };
        i = if x[gt - 1] == b'/' { gt + 1 } else { pdf::find(x, gt, close.as_bytes()).map_or(x.len(), |c| c + close.len()) };
        removed = true;
    }
    out.extend_from_slice(&x[i.min(x.len())..]);
    (out, removed)
}

/// Removes the `<Relationship .../>` elements whose Type ends with `/kind`.
fn remove_relationships(x: &[u8], kind: &str) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(x.len());
    let mut i = 0;
    let mut removed = false;
    while let Some(p) = pdf::find(x, i, b"<Relationship ") {
        let Some(gt) = x[p..].iter().position(|&b| b == b'>').map(|g| p + g) else { break };
        let tag = String::from_utf8_lossy(&x[p..=gt]);
        let ty = tag.split("Type=\"").nth(1).and_then(|t| t.split('"').next()).unwrap_or("");
        out.extend_from_slice(&x[i..p]);
        if ty.ends_with(&format!("/{kind}")) {
            removed = true;
        } else {
            out.extend_from_slice(&x[p..=gt]);
        }
        i = gt + 1;
    }
    out.extend_from_slice(&x[i..]);
    (out, removed)
}

/// An OpenDocument config item by name, removed.
fn remove_config_items(x: &[u8], names: &[&str]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(x.len());
    let mut i = 0;
    let mut removed = false;
    while let Some(p) = pdf::find(x, i, b"<config:config-item ") {
        let Some(gt) = x[p..].iter().position(|&b| b == b'>').map(|g| p + g) else { break };
        let tag = String::from_utf8_lossy(&x[p..=gt]);
        let name = tag.split("config:name=\"").nth(1).and_then(|t| t.split('"').next()).unwrap_or("");
        let end = if x[gt - 1] == b'/' { gt + 1 } else { pdf::find(x, gt, b"</config:config-item>").map_or(x.len(), |c| c + 21) };
        out.extend_from_slice(&x[i..p]);
        if names.contains(&name) {
            removed = true;
        } else {
            out.extend_from_slice(&x[p..end]);
        }
        i = end;
    }
    out.extend_from_slice(&x[i.min(x.len())..]);
    (out, removed)
}

fn entries_note(a: &zip::Archive, r: &mut Removed) {
    if !a.comment.is_empty() || a.entries.iter().any(|e| e.comment_len > 0) {
        note(r, "Archive comments");
    }
    if a.entries.iter().any(|e| e.extra_len > 0) {
        note(r, "Extra file details (exact times, owner ids)");
    }
    if a.entries.iter().any(|e| e.date != zip::DOS_DATE || e.time != zip::DOS_TIME) {
        note(r, "File times");
    }
}

fn check_zip(a: &zip::Archive) -> Result<(), String> {
    if a.entries.iter().any(|e| e.encrypted()) {
        return Err("it has encrypted files; it is not changed".into());
    }
    Ok(())
}

const CORE_EMPTY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>"#;
const APP_EMPTY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>"#;
const CUSTOM_EMPTY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>"#;

pub fn office(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let src = &d;
    let a = zip::read(src)?;
    check_zip(&a)?;
    let mut budget = 4 * PART;
    let mut w = zip::Writer::new(Vec::with_capacity(d.len()));
    for e in &a.entries {
        let name = e.name_lossy();
        let new: Option<Vec<u8>> = match name.as_str() {
            "docProps/core.xml" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                for (tag, what) in [
                    ("creator", "Author"),
                    ("lastmodifiedby", "Last modified by"),
                    ("revision", "Revision number"),
                    ("created", "Created and modified dates"),
                    ("modified", "Created and modified dates"),
                    ("lastprinted", "Last printed"),
                    ("title", "Title, subject, keywords or description"),
                    ("subject", "Title, subject, keywords or description"),
                    ("keywords", "Title, subject, keywords or description"),
                    ("description", "Title, subject, keywords or description"),
                    ("category", "Category and status"),
                    ("contentstatus", "Category and status"),
                ] {
                    if has_tag(&x, tag) {
                        note(r, what);
                    }
                }
                Some(CORE_EMPTY.to_vec())
            }
            "docProps/app.xml" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                for (tag, what) in [
                    ("company", "Company"),
                    ("manager", "Manager"),
                    ("template", "Template name"),
                    ("totaltime", "Editing time"),
                    ("application", "Program and version"),
                    ("appversion", "Program and version"),
                    ("hyperlinkbase", "Link base address"),
                ] {
                    if has_tag(&x, tag) {
                        note(r, what);
                    }
                }
                Some(APP_EMPTY.to_vec())
            }
            "docProps/custom.xml" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                if has_tag(&x, "property") {
                    note(r, "Custom properties");
                }
                Some(CUSTOM_EMPTY.to_vec())
            }
            "word/settings.xml" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                let (x, t) = remove_elements(&x, "w:attachedTemplate");
                let (x, s) = remove_elements(&x, "w:rsids");
                if t {
                    note(r, "Template path (it can hold your user name)");
                }
                if s {
                    note(r, "Editing session ids (rsid list)");
                }
                (t || s).then_some(x)
            }
            "word/_rels/settings.xml.rels" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                let (x, t) = remove_relationships(&x, "attachedTemplate");
                if t {
                    note(r, "Template path (it can hold your user name)");
                }
                t.then_some(x)
            }
            "xl/workbook.xml" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                let (x, t) = remove_elements(&x, "x15ac:absPath");
                if t {
                    note(r, "The folder the workbook was saved in");
                }
                t.then_some(x)
            }
            _ => None,
        };
        match new {
            Some(c) => w.file(&e.name, &c, false),
            None => w.raw(&e.name, e.method, e.crc, e.usize, &zip::raw(src, e, u32::MAX as u64)?),
        }
        .map_err(|e| e.to_string())?;
    }
    entries_note(&a, r);
    w.finish().map_err(|e| e.to_string())
}

pub fn odf(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let src = &d;
    let a = zip::read(src)?;
    check_zip(&a)?;
    let mut budget = 4 * PART;
    let mut w = zip::Writer::new(Vec::with_capacity(d.len()));
    // "mimetype" first and stored, as OpenDocument requires
    let mime = a.find("mimetype").ok_or("no mimetype")?;
    w.file(b"mimetype", &zip::content(src, mime, 4096, &mut budget)?, true).map_err(|e| e.to_string())?;
    for e in a.entries.iter().filter(|e| e.name != b"mimetype") {
        let name = e.name_lossy();
        let new = match name.as_str() {
            "meta.xml" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                let tags = markup::tags(&x, 100_000);
                let version = tags.iter().find_map(|t| t.attr("office:version").map(str::to_string)).unwrap_or_else(|| "1.2".into());
                for t in &tags {
                    let what = match t.name.as_str() {
                        "meta:initial-creator" | "dc:creator" => "Author",
                        "meta:creation-date" | "dc:date" | "meta:print-date" => "Dates",
                        "meta:editing-cycles" => "Revision count",
                        "meta:editing-duration" => "Editing time",
                        "meta:generator" => "Program and version",
                        "meta:template" => "Template path (it can hold your user name)",
                        "meta:printed-by" => "Printed by",
                        "meta:user-defined" => "Custom properties",
                        "dc:title" | "dc:subject" | "dc:description" | "meta:keyword" => "Title, subject, keywords or description",
                        "meta:hyperlink-behaviour" | "meta:auto-reload" => "Other properties",
                        _ => continue,
                    };
                    note(r, what);
                }
                let v: String = version.chars().filter(|c| c.is_ascii_digit() || *c == '.').take(8).collect();
                Some(
                    format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<office:document-meta xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" office:version=\"{v}\"><office:meta/></office:document-meta>"
                    )
                    .into_bytes(),
                )
            }
            "settings.xml" => {
                let x = zip::content(src, e, PART, &mut budget)?;
                let (x, t) = remove_config_items(&x, &["PrinterName", "PrinterSetup", "PrinterPaperFromSetup"]);
                if t {
                    note(r, "Printer name and setup");
                }
                t.then_some(x)
            }
            _ => None,
        };
        match new {
            Some(c) => w.file(&e.name, &c, false),
            None => w.raw(&e.name, e.method, e.crc, e.usize, &zip::raw(src, e, u32::MAX as u64)?),
        }
        .map_err(|e| e.to_string())?;
    }
    entries_note(&a, r);
    w.finish().map_err(|e| e.to_string())
}

/// A plain ZIP archive: the same files, without comments, extra fields, times or owners.
pub fn plain_zip(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let src = &d;
    let a = zip::read(src)?;
    check_zip(&a)?;
    let mut w = zip::Writer::new(Vec::with_capacity(d.len()));
    for e in &a.entries {
        w.raw(&e.name, e.method, e.crc, e.usize, &zip::raw(src, e, u32::MAX as u64)?).map_err(|e| e.to_string())?;
    }
    entries_note(&a, r);
    if a.entries.iter().any(|e| e.made_by >> 8 == 3 && e.external >> 16 != 0 && !matches!(e.external >> 16, 0o100644 | 0o040755)) {
        note(r, "File permissions");
    }
    w.finish().map_err(|e| e.to_string())
}

// ---- PDF ----

/// Keys removed from every dictionary: XMP streams' pointers, applications' private data, last-changed times.
const PDF_DROP_KEYS: &[&[u8]] = &[b"Metadata", b"PieceInfo", b"LastModified"];

pub fn pdf(d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    let doc = pdf::Doc::scan(d);
    if doc.trailer_has(b"Encrypt") {
        return Err("it is encrypted; encrypted PDFs are not changed".into());
    }
    if !doc.complete {
        return Err("part of it could not be read, so it is not changed".into());
    }
    let root = doc.trailer_ref(b"Root").ok_or("it has no catalogue (damaged?)")?;
    if !doc.objs.contains_key(&root) {
        return Err("its catalogue is missing (damaged?)".into());
    }
    let info = doc.trailer_ref(b"Info");
    if let Some(i) = info.and_then(|i| doc.objs.get(&i)) {
        let t = doc.toks(i);
        let mut keys: Vec<String> = pdf::entries(&t, 0).into_iter().map(|(k, _, _)| String::from_utf8_lossy(&k).into_owned()).collect();
        keys.truncate(12);
        if !keys.is_empty() {
            note(r, &format!("Document information ({})", keys.join(", ")));
        }
    } else if doc.trailers.iter().any(|t| pdf::get(&pdf::entries(t, 0), b"Info").is_some()) {
        note(r, "Document information");
    }
    if doc.trailers.iter().any(|t| pdf::get(&pdf::entries(t, 0), b"ID").is_some()) {
        note(r, "Document id");
    }
    let mut nums: Vec<u32> = doc.objs.keys().copied().collect();
    nums.sort();
    // the cross-reference table has a line per number up to the highest: numbers far beyond the count are damage (or a trap)
    if nums.last().is_some_and(|&m| m as usize > 10 * nums.len() + 10_000) {
        return Err("its object numbers are far beyond its objects (damaged?)".into());
    }
    let mut out = format!("%PDF-{}\n", if doc.version.is_empty() { "1.7" } else { &doc.version }).into_bytes();
    // the second line's bytes above 127 say the file is binary
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<(u32, u16, usize)> = vec![];
    for n in nums {
        if Some(n) == info {
            continue;
        }
        let o = &doc.objs[&n];
        let t = doc.toks(o);
        let es = pdf::entries(&t, 0);
        let ty = pdf::get(&es, b"Type").and_then(|(a, b)| pdf::as_name(&t, a, b)).map(<[u8]>::to_vec);
        match ty.as_deref() {
            Some(b"Metadata") => {
                note(r, "XMP metadata");
                continue;
            }
            Some(b"XRef") | Some(b"ObjStm") => continue,
            _ => {}
        }
        if pdf::get(&es, b"Linearized").is_some() {
            continue;
        }
        // the value without the dropped keys, and a stream's /Length written as the real length
        let buf = doc.buf(o);
        let mut cuts: Vec<(usize, usize, Vec<u8>)> = vec![];
        // the object's own dictionary: where catalogues, pages and pictures keep these keys
        for (k, a, b) in &es {
            if PDF_DROP_KEYS.contains(&k.as_slice()) {
                if k == b"PieceInfo" {
                    note(r, "Program's private data (PieceInfo)");
                }
                if k == b"LastModified" {
                    note(r, "Last changed times");
                }
                // from the key (the token before the value) to the value's end
                cuts.push((t[a - 1].start, t[b - 1].end, vec![b' ']));
            }
        }
        let stream = o.stream.map(|(s, e)| &d[s..e]);
        if let (Some(s), Some((a, b))) = (stream, pdf::get(&es, b"Length")) {
            let (vs, ve) = (t[a].start, t[b - 1].end);
            cuts.push((vs, ve, s.len().to_string().into_bytes()));
        }
        cuts.sort_by_key(|c| c.0);
        let mut body = vec![];
        let mut at = o.body.0;
        for (s, e, with) in cuts {
            if s < at {
                continue; // inside a value already cut
            }
            body.extend_from_slice(&buf[at..s]);
            body.extend_from_slice(&with);
            at = e;
        }
        body.extend_from_slice(&buf[at.min(o.body.1)..o.body.1]);
        offsets.push((n, o.gen, out.len()));
        out.extend_from_slice(format!("{} {} obj\n", n, o.gen).as_bytes());
        out.extend_from_slice(trim(&body));
        if let Some(s) = stream {
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(s);
            out.extend_from_slice(b"\nendstream");
        }
        out.extend_from_slice(b"\nendobj\n");
    }
    let size = offsets.iter().map(|o| o.0).max().unwrap_or(0) + 1;
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    let mut k = 0;
    for n in 0..size {
        if k < offsets.len() && offsets[k].0 == n {
            out.extend_from_slice(format!("{:010} {:05} n \n", offsets[k].2, offsets[k].1).as_bytes());
            k += 1;
        } else {
            out.extend_from_slice(b"0000000000 65535 f \n");
        }
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root {root} {} R >>\nstartxref\n{xref}\n%%EOF\n", doc.objs[&root].gen).as_bytes(),
    );
    Ok(out)
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let e = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(s, |p| p + 1);
    &b[s..e.max(s)]
}
