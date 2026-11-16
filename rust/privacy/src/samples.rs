//! Made-up files for the tests and the fuzz seeds: documents that call servers, pictures and songs with a fake GPS position,
//! a fake camera, a fake author. Nothing here is anyone's real data: the place is the Eiffel Tower's public coordinates, the
//! names are placeholders ("Jane Roe", "Example Corp"), the servers are example.com/.net/.org (reserved, they reach no one).

use crate::zip::Writer;

pub const AUTHOR: &str = "Jane Roe";
pub const COMPANY: &str = "Example Corp";
pub const EVIL: &str = "http://tracker.example.net/t.dotm";

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = Writer::new(Vec::new());
    for (n, c) in files {
        w.file(n.as_bytes(), c, *n == "mimetype").unwrap();
    }
    w.finish().unwrap()
}

/// A Word document: its author, company and template in docProps; with `remote`, a template on a server and a remote picture.
pub fn docx(remote: bool) -> Vec<u8> {
    let settings_rels = format!(
        r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="{}" TargetMode="External"/></Relationships>"#,
        if remote { EVIL } else { "file:///C:/Users/jroe/AppData/Roaming/Microsoft/Templates/Normal.dotm" }
    );
    let doc_rels = if remote {
        r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://img.example.com/pixel.png" TargetMode="External"/><Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/click" TargetMode="External"/></Relationships>"#
    } else {
        r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/click" TargetMode="External"/></Relationships>"#
    };
    let core = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Plans</dc:title><dc:creator>{AUTHOR}</dc:creator><cp:lastModifiedBy>{AUTHOR}</cp:lastModifiedBy><cp:revision>7</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2026-01-02T03:04:05Z</dcterms:created></cp:coreProperties>"#
    );
    let app = format!(
        r#"<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Template>Normal.dotm</Template><TotalTime>42</TotalTime><Company>{COMPANY}</Company><Application>Microsoft Office Word</Application></Properties>"#
    );
    let doc = br#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>"#;
    let settings = br#"<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:attachedTemplate r:id="rId1"/><w:rsids><w:rsidRoot w:val="00A1B2C3"/></w:rsids></w:settings>"#;
    zip(&[
        ("[Content_Types].xml", br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#),
        ("_rels/.rels", br#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#),
        ("word/document.xml", doc),
        ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
        ("word/settings.xml", settings),
        ("word/_rels/settings.xml.rels", settings_rels.as_bytes()),
        ("docProps/core.xml", core.as_bytes()),
        ("docProps/app.xml", app.as_bytes()),
    ])
}

/// A Word document whose INCLUDEPICTURE field is split over runs.
pub fn docx_field() -> Vec<u8> {
    let doc = br#"<?xml version="1.0"?><w:document xmlns:w="w"><w:body><w:p><w:r><w:instrText> INCLUDEPICTURE "http://img.exa</w:instrText></w:r><w:r><w:instrText>mple.com/a.png" \d </w:instrText></w:r></w:p></w:body></w:document>"#;
    zip(&[("[Content_Types].xml", b"<Types/>"), ("word/document.xml", doc)])
}

/// An OpenDocument text: its author in meta.xml, a printer in settings.xml; with `remote`, a linked picture on a server.
pub fn odt(remote: bool) -> Vec<u8> {
    let content = format!(
        r#"<?xml version="1.0"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text><text:p>Hi <text:a xlink:href="https://example.org/click">link</text:a></text:p>{}</office:text></office:body></office:document-content>"#,
        if remote {
            r#"<draw:frame><draw:image xlink:href="https://img.example.com/beacon.png" xlink:type="simple"/></draw:frame>"#
        } else {
            ""
        }
    );
    let meta = format!(
        r#"<?xml version="1.0"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3"><office:meta><meta:initial-creator>{AUTHOR}</meta:initial-creator><dc:creator>{AUTHOR}</dc:creator><meta:editing-cycles>9</meta:editing-cycles><meta:generator>LibreOffice/7.6</meta:generator></office:meta></office:document-meta>"#
    );
    let settings = br#"<?xml version="1.0"?><office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0"><office:settings><config:config-item-set config:name="ooo:configuration-settings"><config:config-item config:name="PrinterName" config:type="string">Office-Printer-3F</config:config-item><config:config-item config:name="PrinterSetup" config:type="base64Binary">AAAA</config:config-item><config:config-item config:name="EmbedFonts" config:type="boolean">false</config:config-item></config:config-item-set></office:settings></office:document-settings>"#;
    zip(&[
        ("mimetype", b"application/vnd.oasis.opendocument.text"),
        (
            "META-INF/manifest.xml",
            br#"<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>"#,
        ),
        ("content.xml", content.as_bytes()),
        ("meta.xml", meta.as_bytes()),
        ("settings.xml", settings),
    ])
}

/// A PDF of numbered objects with a correct cross-reference table; the trailer gets /Root 1 0 R and the extra text given.
pub fn pdf_from(objs: &[&str], trailer_extra: &str) -> Vec<u8> {
    let mut f = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offs = vec![];
    for (i, o) in objs.iter().enumerate() {
        offs.push(f.len());
        f.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let x = f.len();
    f.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offs {
        f.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    f.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R {trailer_extra} >>\nstartxref\n{x}\n%%EOF\n", objs.len() + 1).as_bytes());
    f
}

/// A one-page PDF with document information (author, producer), XMP, and with `auto` an /OpenAction that opens a web address.
pub fn pdf(auto: bool) -> Vec<u8> {
    let xmp = format!("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><dc:creator>{AUTHOR}</dc:creator></x:xmpmeta>");
    let catalog = if auto {
        "<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R /OpenAction 6 0 R >>"
    } else {
        "<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>"
    };
    let meta = format!("<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n{xmp}\nendstream", xmp.len());
    let content = "BT /F1 12 Tf 10 10 Td (Hello) Tj ET";
    let page_content = format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len());
    let info = format!("<< /Author ({AUTHOR}) /Producer (Example Writer 1.0) /CreationDate (D:20260102030405Z) /Title (Plans) >>");
    pdf_from(
        &[
            catalog,
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 7 0 R /Annots [8 0 R] >>",
            &info,
            &meta,
            "<< /S /URI /URI (https://tracker.example.net/opened?id=1) >>",
            &page_content,
            "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (https://example.org/click) >> >>",
        ],
        "/Info 4 0 R /ID [<00112233445566778899AABBCCDDEEFF> <00112233445566778899AABBCCDDEEFF>]",
    )
}

// ---- pictures ----

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// A big-endian TIFF/EXIF block: IFD0 with Make, Model, Orientation 6, Software, a pointer to an EXIF IFD (DateTimeOriginal,
/// a maker note, a serial number) and to a GPS IFD (the Eiffel Tower, 48°51'29.6"N 2°17'40.2"E).
pub fn exif_tiff() -> Vec<u8> {
    // layout: header 8, IFD0 at 8 with 6 entries (2 + 6*12 + 4 = 78) -> 86; then the data area
    let mut data: Vec<u8> = vec![];
    let data_base = 8 + 2 + 6 * 12 + 4;
    let mut put = |b: &[u8]| -> u32 {
        let at = data_base + data.len();
        data.extend_from_slice(b);
        if data.len() % 2 == 1 {
            data.push(0);
        }
        at as u32
    };
    let make = put(b"FakeCam\0");
    let model = put(b"FakeCam Pro 9\0");
    let software = put(b"FakeFirmware 1.2\0");
    // EXIF IFD: 3 entries
    let date = put(b"2026:01:02 03:04:05\0");
    let maker = put(b"FAKEMAKERNOTE-SERIAL-0042");
    let serial = put(b"SN0042\0");
    let exif_ifd_at = data_base + data.len();
    let mut exif = vec![];
    exif.extend_from_slice(&be16(3));
    for (tag, ty, count, val) in [(0x9003u16, 2u16, 20u32, date), (0x927C, 7, 25, maker), (0xA431, 2, 7, serial)] {
        exif.extend_from_slice(&be16(tag));
        exif.extend_from_slice(&be16(ty));
        exif.extend_from_slice(&be32(count));
        exif.extend_from_slice(&be32(val));
    }
    exif.extend_from_slice(&be32(0));
    data.extend_from_slice(&exif);
    // GPS IFD: LatitudeRef N, Latitude 48/1 51/1 296/10, LongitudeRef E, Longitude 2/1 17/1 402/10
    let rat_base = data_base + data.len() + 2 + 5 * 12 + 4;
    let lat_at = rat_base as u32;
    let lon_at = lat_at + 24;
    let mut gps = vec![];
    gps.extend_from_slice(&be16(5));
    gps.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 4, 2, 2, 0, 0]); // GPSVersionID 2.2.0.0
    gps.extend_from_slice(&[0, 1, 0, 2, 0, 0, 0, 2, b'N', 0, 0, 0]);
    gps.extend_from_slice(&[0, 2, 0, 5, 0, 0, 0, 3]);
    gps.extend_from_slice(&be32(lat_at));
    gps.extend_from_slice(&[0, 3, 0, 2, 0, 0, 0, 2, b'E', 0, 0, 0]);
    gps.extend_from_slice(&[0, 4, 0, 5, 0, 0, 0, 3]);
    gps.extend_from_slice(&be32(lon_at));
    gps.extend_from_slice(&be32(0));
    for (n, d) in [(48u32, 1u32), (51, 1), (296, 10), (2, 1), (17, 1), (402, 10)] {
        gps.extend_from_slice(&be32(n));
        gps.extend_from_slice(&be32(d));
    }
    let gps_ifd_at = data_base + data.len();
    data.extend_from_slice(&gps);
    let mut t = b"MM\0\x2A".to_vec();
    t.extend_from_slice(&be32(8));
    t.extend_from_slice(&be16(6));
    for (tag, ty, count, val) in [
        (0x010Fu16, 2u16, 8u32, make),
        (0x0110, 2, 14, model),
        (0x0112, 3, 1, 6u32 << 16),
        (0x0131, 2, 17, software),
        (0x8769, 4, 1, exif_ifd_at as u32),
        (0x8825, 4, 1, gps_ifd_at as u32),
    ] {
        t.extend_from_slice(&be16(tag));
        t.extend_from_slice(&be16(ty));
        t.extend_from_slice(&be32(count));
        t.extend_from_slice(&be32(val));
    }
    t.extend_from_slice(&be32(0));
    assert_eq!(t.len(), data_base);
    t.extend_from_slice(&data);
    t
}

/// XMP with a creator and a GPS position.
pub fn xmp() -> Vec<u8> {
    format!(
        r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:exif="http://ns.adobe.com/exif/1.0/" exif:GPSLatitude="48,51.493N" exif:GPSLongitude="2,17.670E"><dc:creator>{AUTHOR}</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>"#
    )
    .into_bytes()
}

fn seg(marker: u8, body: &[u8]) -> Vec<u8> {
    let mut s = vec![0xFF, marker];
    s.extend_from_slice(&be16((body.len() + 2) as u16));
    s.extend_from_slice(body);
    s
}

/// The metadata segments a camera and an editor leave in a JPEG: EXIF (with GPS), XMP, Photoshop/IPTC, a comment, and an
/// ICC profile that must stay.
pub fn jpeg_segments() -> Vec<u8> {
    let mut v = vec![];
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend_from_slice(&exif_tiff());
    v.extend(seg(0xE1, &exif));
    let mut x = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    x.extend_from_slice(&xmp());
    v.extend(seg(0xE1, &x));
    let mut iptc = b"Photoshop 3.0\08BIM\x04\x04\0\0\0\0\0\x10\x1C\x02\x5A\0\x05Paris\x1C\x02\x50\0\x03JRO".to_vec();
    iptc.push(0);
    v.extend(seg(0xED, &iptc));
    v.extend(seg(0xFE, format!("Taken by {AUTHOR}").as_bytes()));
    let mut icc = b"ICC_PROFILE\0\x01\x01".to_vec();
    icc.extend_from_slice(&[0u8; 32]);
    v.extend(seg(0xE2, &icc));
    v
}

/// A structurally complete JPEG (its picture data is not a real picture) with every metadata segment.
pub fn jpeg() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    v.extend(seg(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"));
    v.extend(jpeg_segments());
    v.extend(seg(0xDB, &[0u8; 65]));
    v.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
    v.extend(seg(0xDA, &[1, 1, 0, 0, 63, 0]));
    v.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0x56]);
    v.extend_from_slice(&[0xFF, 0xD9]);
    // what some phones append after the picture: a second picture (a depth map, a preview) with its own metadata
    v.extend_from_slice(b"\xFF\xD8\xFF\xE1\x00\x08Exif\x00\x00\xFF\xD9");
    v
}

fn png_chunk(ty: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut c = be32(body.len() as u32).to_vec();
    c.extend_from_slice(ty);
    c.extend_from_slice(body);
    let mut crc = flate2::Crc::new();
    crc.update(ty);
    crc.update(body);
    c.extend_from_slice(&be32(crc.sum()));
    c
}

/// A real 1x1 grey PNG with text (author), XMP in iTXt, EXIF (GPS), a time stamp and a private chunk.
pub fn png() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
    v.extend(png_chunk(b"gAMA", &be32(45455)));
    v.extend(png_chunk(b"tEXt", format!("Author\0{AUTHOR}").as_bytes()));
    let mut itxt = b"XML:com.adobe.xmp\0\0\0\0\0".to_vec();
    itxt.extend_from_slice(&xmp());
    v.extend(png_chunk(b"iTXt", &itxt));
    v.extend(png_chunk(b"eXIf", &exif_tiff()));
    v.extend(png_chunk(b"tIME", &[0x07, 0xEA, 1, 2, 3, 4, 5]));
    v.extend(png_chunk(b"prVt", b"private"));
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut z, &[0, 0x80]).unwrap();
    v.extend(png_chunk(b"IDAT", &z.finish().unwrap()));
    v.extend(png_chunk(b"IEND", b""));
    v
}

fn riff_chunk(id: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut c = id.to_vec();
    c.extend_from_slice(&(body.len() as u32).to_le_bytes());
    c.extend_from_slice(body);
    if body.len() % 2 == 1 {
        c.push(0);
    }
    c
}

/// An extended WebP (VP8X with the EXIF and XMP flags) with EXIF and XMP chunks; its picture chunk is a stand-in.
pub fn webp() -> Vec<u8> {
    let mut body = b"WEBP".to_vec();
    body.extend(riff_chunk(b"VP8X", &[0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    body.extend(riff_chunk(b"VP8L", &[0x2F, 0, 0, 0, 0x10, 0x07, 0x10, 0x11, 0x11, 0x88, 0x88, 0xFE, 0x07, 0]));
    body.extend(riff_chunk(b"EXIF", &exif_tiff()));
    body.extend(riff_chunk(b"XMP ", &xmp()));
    let mut v = b"RIFF".to_vec();
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&body);
    v
}

/// A baseline TIFF (1x1 grey, one strip) whose first IFD also has Make, Model, Artist, Software and a GPS IFD.
pub fn tiff() -> Vec<u8> {
    // II, IFD0 at 8: 12 entries -> 8 + 2 + 144 + 4 = 158; then data
    let n = 12u16;
    let base = 8 + 2 + n as usize * 12 + 4;
    let mut data = vec![];
    let mut put = |b: &[u8]| -> u32 {
        let at = base + data.len();
        data.extend_from_slice(b);
        if data.len() % 2 == 1 {
            data.push(0);
        }
        at as u32
    };
    let pixel = put(&[0x80]);
    let make = put(b"FakeCam\0");
    let model = put(b"FakeCam Pro 9\0");
    let artist = put(format!("{AUTHOR}\0").as_bytes());
    let soft = put(b"FakeFirmware 1.2\0");
    let gps_at = base + data.len();
    // GPS IFD, little-endian: LatitudeRef only (enough to be found)
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&[1, 0, 2, 0, 2, 0, 0, 0, b'N', 0, 0, 0]);
    data.extend_from_slice(&0u32.to_le_bytes());
    let mut t = b"II\x2A\0".to_vec();
    t.extend_from_slice(&8u32.to_le_bytes());
    t.extend_from_slice(&n.to_le_bytes());
    let e = |t: &mut Vec<u8>, tag: u16, ty: u16, count: u32, val: u32| {
        t.extend_from_slice(&tag.to_le_bytes());
        t.extend_from_slice(&ty.to_le_bytes());
        t.extend_from_slice(&count.to_le_bytes());
        t.extend_from_slice(&val.to_le_bytes());
    };
    e(&mut t, 256, 3, 1, 1);
    e(&mut t, 257, 3, 1, 1);
    e(&mut t, 258, 3, 1, 8);
    e(&mut t, 259, 3, 1, 1);
    e(&mut t, 262, 3, 1, 1);
    e(&mut t, 271, 2, 8, make);
    e(&mut t, 272, 2, 14, model);
    e(&mut t, 273, 4, 1, pixel);
    e(&mut t, 278, 3, 1, 1);
    e(&mut t, 279, 4, 1, 1);
    e(&mut t, 305, 2, 17, soft);
    e(&mut t, 315, 2, 9, artist);
    // the GPS pointer makes 13: rewrite the count
    t[8..10].copy_from_slice(&(n + 1).to_le_bytes());
    e(&mut t, 34853, 4, 1, (gps_at + 12) as u32);
    t.extend_from_slice(&0u32.to_le_bytes());
    // everything after the IFD moved by the extra entry's 12 bytes
    let shift = 12u32;
    let mut out = t;
    let fix = |out: &mut Vec<u8>, entry: usize| {
        let p = 10 + entry * 12 + 8;
        let v = u32::from_le_bytes(out[p..p + 4].try_into().unwrap()) + shift;
        out[p..p + 4].copy_from_slice(&v.to_le_bytes());
    };
    for entry in [5, 6, 7, 10, 11] {
        fix(&mut out, entry);
    }
    out.extend_from_slice(&data);
    out
}

fn bmff_box(ty: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut b = be32((body.len() + 8) as u32).to_vec();
    b.extend_from_slice(ty);
    b.extend_from_slice(body);
    b
}

fn full_box(ty: &[u8; 4], version: u8, body: &[u8]) -> Vec<u8> {
    let mut b = vec![version, 0, 0, 0];
    b.extend_from_slice(body);
    bmff_box(ty, &b)
}

/// A HEIF structure as a phone writes it: a primary picture item, an Exif item (with GPS) and an XMP item, located in mdat.
pub fn heic() -> Vec<u8> {
    let mut exif_item = vec![0, 0, 0, 0];
    exif_item.extend_from_slice(&exif_tiff());
    let xmp_item = xmp();
    let pict = vec![0xAAu8; 16];
    let ftyp = bmff_box(b"ftyp", b"heic\0\0\0\0mif1heic");
    let hdlr = full_box(b"hdlr", 0, b"\0\0\0\0pict\0\0\0\0\0\0\0\0\0\0\0\0\0");
    let pitm = full_box(b"pitm", 0, &be16(1));
    let infe = |id: u16, ty: &[u8; 4], extra: &[u8]| {
        let mut b = be16(id).to_vec();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(ty);
        b.push(0);
        b.extend_from_slice(extra);
        full_box(b"infe", 2, &b)
    };
    let mut iinf_body = be16(3).to_vec();
    iinf_body.extend(infe(1, b"hvc1", b""));
    iinf_body.extend(infe(2, b"Exif", b""));
    iinf_body.extend(infe(3, b"mime", b"application/rdf+xml\0"));
    let iinf = full_box(b"iinf", 0, &iinf_body);
    // iloc version 0, offset_size 4, length_size 4, base_offset_size 0; offsets patched below
    let iloc_len = 8 + 4 + 2 + 2 + 3 * (2 + 2 + 2 + 4 + 4);
    let meta_len = 12 + hdlr.len() + pitm.len() + iinf.len() + iloc_len;
    let mdat_data_at = ftyp.len() + meta_len + 8;
    let offs = [mdat_data_at, mdat_data_at + pict.len(), mdat_data_at + pict.len() + exif_item.len()];
    let lens = [pict.len(), exif_item.len(), xmp_item.len()];
    let mut iloc_body = vec![0x44, 0x00];
    iloc_body.extend_from_slice(&be16(3));
    for i in 0..3 {
        iloc_body.extend_from_slice(&be16(i as u16 + 1));
        iloc_body.extend_from_slice(&be16(0));
        iloc_body.extend_from_slice(&be16(1));
        iloc_body.extend_from_slice(&be32(offs[i] as u32));
        iloc_body.extend_from_slice(&be32(lens[i] as u32));
    }
    let iloc = full_box(b"iloc", 0, &iloc_body);
    assert_eq!(iloc.len(), iloc_len);
    let mut meta_body = hdlr;
    meta_body.extend(pitm);
    meta_body.extend(iinf);
    meta_body.extend(iloc);
    let meta = full_box(b"meta", 0, &meta_body);
    assert_eq!(meta.len(), meta_len);
    let mut mdat_body = pict;
    mdat_body.extend_from_slice(&exif_item);
    mdat_body.extend_from_slice(&xmp_item);
    let mut v = ftyp;
    v.extend(meta);
    v.extend(bmff_box(b"mdat", &mdat_body));
    v
}

// ---- sound ----

fn synchsafe(n: u32) -> [u8; 4] {
    [((n >> 21) & 0x7F) as u8, ((n >> 14) & 0x7F) as u8, ((n >> 7) & 0x7F) as u8, (n & 0x7F) as u8]
}

/// An MP3 with ID3v2.3 (title, artist, a comment with the place, a cover), stand-in frames, APEv2 and ID3v1 at the end.
pub fn mp3() -> Vec<u8> {
    let frame = |id: &[u8; 4], body: &[u8]| {
        let mut f = id.to_vec();
        f.extend_from_slice(&be32(body.len() as u32));
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(body);
        f
    };
    let mut tags = vec![];
    tags.extend(frame(b"TIT2", b"\0Voice memo"));
    tags.extend(frame(b"TPE1", format!("\0{AUTHOR}").as_bytes()));
    tags.extend(frame(b"COMM", b"\0eng\0Recorded at 48.8584 2.2945"));
    tags.extend(frame(b"APIC", b"\0image/png\0\x03\0\x89PNG"));
    let mut v = b"ID3\x03\0\0".to_vec();
    v.extend_from_slice(&synchsafe(tags.len() as u32));
    v.extend(tags);
    // two MPEG-1 layer III frame headers with stand-in data (128 kbit/s, 44.1 kHz: 417 bytes each)
    for _ in 0..2 {
        let mut f = vec![0xFF, 0xFB, 0x90, 0x64];
        f.resize(417, 0x55);
        v.extend(f);
    }
    let mut ape = b"APETAGEX".to_vec();
    ape.extend_from_slice(&2000u32.to_le_bytes());
    ape.extend_from_slice(&32u32.to_le_bytes()); // size: footer only, no items
    ape.extend_from_slice(&0u32.to_le_bytes());
    ape.extend_from_slice(&0u32.to_le_bytes());
    ape.extend_from_slice(&[0u8; 8]);
    v.extend(ape);
    let mut v1 = b"TAG".to_vec();
    v1.extend_from_slice(&{
        let mut t = [0u8; 125];
        t[..10].copy_from_slice(b"Voice memo");
        t[30..38].copy_from_slice(b"Jane Roe");
        t
    });
    v.extend(v1);
    v
}

/// A FLAC with STREAMINFO, a seek table, Vorbis comments (artist, location), a picture, padding and stand-in frames.
pub fn flac() -> Vec<u8> {
    let block = |ty: u8, last: bool, body: &[u8]| {
        let mut b = vec![ty | if last { 0x80 } else { 0 }];
        b.extend_from_slice(&be32(body.len() as u32)[1..]);
        b.extend_from_slice(body);
        b
    };
    let mut vc = vec![];
    let vendor = b"reference libFLAC 1.4.3";
    vc.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    vc.extend_from_slice(vendor);
    let comments = [format!("ARTIST={AUTHOR}"), "LOCATION=Paris".to_string()];
    vc.extend_from_slice(&(comments.len() as u32).to_le_bytes());
    for c in &comments {
        vc.extend_from_slice(&(c.len() as u32).to_le_bytes());
        vc.extend_from_slice(c.as_bytes());
    }
    let mut v = b"fLaC".to_vec();
    v.extend(block(
        0,
        false,
        &[0x10, 0, 0x10, 0, 0, 0, 0x0E, 0, 0, 0x10, 0x0A, 0xC4, 0x42, 0xF0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ));
    v.extend(block(3, false, &[0u8; 18]));
    v.extend(block(4, false, &vc));
    v.extend(block(6, false, b"\0\0\0\x03\0\0\0\x09image/png\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x08\0\0\0\0\0\0\0\x04\x89PNG"));
    v.extend(block(1, true, &[0u8; 64]));
    v.extend_from_slice(&[0xFF, 0xF8, 0x69, 0x08, 0x00, 0x00, 0x00, 0x00]);
    v
}

/// A WAV with fmt, a broadcast extension (originator, date), LIST/INFO (artist), an id3 chunk and data.
pub fn wav() -> Vec<u8> {
    let mut body = b"WAVE".to_vec();
    body.extend(riff_chunk(b"fmt ", &[1, 0, 1, 0, 0x44, 0xAC, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0]));
    let mut bext = vec![0u8; 602];
    bext[..12].copy_from_slice(b"Field record");
    bext[256..264].copy_from_slice(b"Jane Roe");
    bext[320..330].copy_from_slice(b"2026-01-02");
    body.extend(riff_chunk(b"bext", &bext));
    let mut info = b"INFO".to_vec();
    info.extend(riff_chunk(b"IART", format!("{AUTHOR}\0").as_bytes()));
    body.extend(riff_chunk(b"LIST", &info));
    body.extend(riff_chunk(b"data", &[0u8; 32]));
    body.extend(riff_chunk(b"id3 ", b"ID3\x03\0\0\0\0\0\0"));
    let mut v = b"RIFF".to_vec();
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend(body);
    v
}

/// A ZIP archive with a comment, extra fields, real times and a Unix owner: what `heimdall-strip` normalises.
pub fn plain_zip() -> Vec<u8> {
    let z = zip(&[("notes.txt", b"hello"), ("photos/", b"")]);
    // put a comment on the archive (the end record is the last 22 bytes; its comment length is the last 2)
    let mut z = z;
    let n = z.len();
    let comment = format!("made by {AUTHOR}");
    z[n - 2..].copy_from_slice(&(comment.len() as u16).to_le_bytes());
    z.extend_from_slice(comment.as_bytes());
    z
}
