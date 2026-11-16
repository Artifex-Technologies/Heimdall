use super::*;
use crate::samples;
use crate::zip;

fn has(r: &Removed, s: &str) -> bool {
    r.iter().any(|x| x.contains(s))
}

fn no_secret(b: &[u8]) {
    for s in [&b"Jane Roe"[..], b"FakeCam", b"Example Corp", b"jroe", b"SN0042", b"Paris"] {
        assert!(!b.windows(s.len()).any(|w| w == s), "{} is still in it", String::from_utf8_lossy(s));
    }
}

/// Every part of a ZIP-based file, unpacked, joined: for looking for what must be gone.
fn unpacked(z: &[u8]) -> Vec<u8> {
    let a = zip::read(&z).unwrap();
    let mut all = vec![];
    let mut budget = 1 << 30;
    for e in &a.entries {
        all.extend(zip::content(&z, e, 1 << 26, &mut budget).unwrap());
    }
    all
}

#[test]
fn jpeg_loses_gps_camera_xmp_iptc_comment_and_keeps_its_look() {
    let mut r = vec![];
    let out = clean(Kind::Jpeg, &samples::jpeg(), &mut r).unwrap();
    for w in [
        "GPS position",
        "Camera make and model",
        "Maker notes",
        "serial numbers",
        "XMP metadata",
        "IPTC",
        "Comment",
        "Data after the picture",
    ] {
        assert!(has(&r, w), "{w}: {r:?}");
    }
    no_secret(&out);
    assert!(out.windows(12).any(|w| w == b"ICC_PROFILE\0"), "the colour profile stays");
    assert!(out.windows(5).any(|w| w == b"JFIF\0"));
    assert!(out.ends_with(b"\xFF\xD9"));
    // the picture is turned (orientation 6): a tiny EXIF says so, and nothing else
    let (what, o) = exif::describe(&out[out.windows(6).position(|w| w == b"Exif\0\0").unwrap() + 6..]);
    assert_eq!(o, 6);
    assert!(what.is_empty());
    let mut again = vec![];
    clean(Kind::Jpeg, &out, &mut again).unwrap();
    assert!(again.is_empty(), "a clean copy has nothing more to remove: {again:?}");
}

#[test]
fn png_loses_text_xmp_exif_time_and_private_chunks() {
    let mut r = vec![];
    let out = clean(Kind::Png, &samples::png(), &mut r).unwrap();
    for w in ["XMP metadata", "Text fields", "GPS position", "Time it was last changed", "Private data (prVt)"] {
        assert!(has(&r, w), "{w}: {r:?}");
    }
    no_secret(&out);
    assert!(out.windows(4).any(|w| w == b"gAMA"));
    assert!(out.windows(4).any(|w| w == b"eXIf"), "the orientation stays");
    let mut again = vec![];
    clean(Kind::Png, &out, &mut again).unwrap();
    assert!(again.is_empty(), "{again:?}");
}

#[test]
fn webp_loses_exif_and_xmp_and_its_flags_say_so() {
    let mut r = vec![];
    let out = clean(Kind::Webp, &samples::webp(), &mut r).unwrap();
    assert!(has(&r, "GPS position") && has(&r, "XMP metadata"), "{r:?}");
    no_secret(&out);
    assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize, out.len() - 8);
    assert_eq!(out[20] & 0x04, 0, "no XMP flag");
    assert_eq!(out[20] & 0x08, 0x08, "the EXIF flag stays for the orientation chunk");
    assert!(!out.windows(4).any(|w| w == b"XMP "));
}

#[test]
fn tiff_keeps_its_picture_and_loses_the_rest() {
    let mut r = vec![];
    let out = clean(Kind::Tiff, &samples::tiff(), &mut r).unwrap();
    for w in ["Camera make and model", "GPS position", "Author and copyright", "Software"] {
        assert!(has(&r, w), "{w}: {r:?}");
    }
    no_secret(&out);
    let mut again = vec![];
    let out2 = clean(Kind::Tiff, &out, &mut again).unwrap();
    assert!(again.is_empty(), "{again:?}");
    assert_eq!(out, out2, "cleaning a clean TIFF changes nothing");
    assert!(out.contains(&0x80), "the pixel is there");
}

#[test]
fn heif_items_are_blanked_in_place() {
    let src = samples::heic();
    let mut r = vec![];
    let out = clean(Kind::Heif, &src, &mut r).unwrap();
    assert!(has(&r, "GPS position") && has(&r, "XMP metadata"), "{r:?}");
    assert_eq!(out.len(), src.len(), "nothing moves, so every offset stays right");
    no_secret(&out);
    assert!(out.windows(16).any(|w| w == [0xAA; 16]), "the picture item is untouched");
}

#[test]
fn pdf_loses_its_information_xmp_and_id_and_still_reads() {
    let mut r = vec![];
    let out = clean(Kind::Pdf, &samples::pdf(false), &mut r).unwrap();
    assert!(has(&r, "Document information (Author, Producer, CreationDate, Title)"), "{r:?}");
    assert!(has(&r, "XMP metadata") && has(&r, "Document id"), "{r:?}");
    no_secret(&out);
    let d = crate::pdf::Doc::scan(&out);
    let root = d.trailer_ref(b"Root").unwrap();
    assert!(d.objs.contains_key(&root) && d.objs.contains_key(&3), "the catalogue and the page are there");
    assert!(!d.trailer_has(b"Info") && !d.trailer_has(b"ID"));
    verify_pdf(&out).unwrap();
    let mut again = vec![];
    clean(Kind::Pdf, &out, &mut again).unwrap();
    assert!(again.is_empty(), "{again:?}");
}

#[test]
fn encrypted_and_damaged_pdfs_are_left_alone() {
    let enc = samples::pdf_from(&["<< /Type /Catalog >>"], "/Encrypt << /Filter /Standard >>");
    assert!(clean(Kind::Pdf, &enc, &mut vec![]).unwrap_err().contains("encrypted"));
    assert!(clean(Kind::Pdf, b"%PDF-1.4 nothing", &mut vec![]).is_err());
}

#[test]
fn office_loses_author_company_template_and_rsids() {
    let mut r = vec![];
    let out = clean(Kind::Office, &samples::docx(false), &mut r).unwrap();
    for w in [
        "Author",
        "Last modified by",
        "Revision number",
        "Company",
        "Template name",
        "Template path",
        "Editing time",
        "Editing session ids",
        "Program and version",
    ] {
        assert!(has(&r, w), "{w}: {r:?}");
    }
    let all = unpacked(&out);
    no_secret(&all);
    assert!(all.windows(5).any(|w| w == b"Hello"), "the text stays");
    let a = zip::read(&out).unwrap();
    assert!(a.entries.iter().all(|e| e.date == zip::DOS_DATE && e.extra_len == 0));
    let mut again = vec![];
    clean(Kind::Office, &out, &mut again).unwrap();
    assert!(again.is_empty(), "{again:?}");
}

#[test]
fn opendocument_loses_meta_and_printer_and_keeps_mimetype_first() {
    let mut r = vec![];
    let out = clean(Kind::OpenDocument, &samples::odt(false), &mut r).unwrap();
    for w in ["Author", "Revision count", "Program and version", "Printer name and setup"] {
        assert!(has(&r, w), "{w}: {r:?}");
    }
    let all = unpacked(&out);
    no_secret(&all);
    assert!(!all.windows(17).any(|w| w == b"Office-Printer-3F"));
    assert!(all.windows(10).any(|w| w == b"EmbedFonts"), "other settings stay");
    let a = zip::read(&out).unwrap();
    assert_eq!(a.entries[0].name, b"mimetype");
    assert_eq!(a.entries[0].method, 0);
    assert!(out[30..38] == *b"mimetype", "its name is right after the first header");
}

#[test]
fn zip_archives_lose_comments_and_times() {
    let mut src = samples::plain_zip();
    // real times on every entry, as a zip tool would write them
    let mut i = 0;
    while let Some(p) = crate::pdf::find(&src, i, b"PK\x01\x02") {
        src[p + 14] = 0x5A;
        i = p + 4;
    }
    let mut r = vec![];
    let out = clean(Kind::Zip, &src, &mut r).unwrap();
    assert!(has(&r, "Archive comments") && has(&r, "File times"), "{r:?}");
    no_secret(&out);
    assert_eq!(unpacked(&out), b"hello");
}

#[test]
fn mp3_flac_wav_lose_their_tags_and_keep_their_sound() {
    let mut r = vec![];
    let out = clean(Kind::Mp3, &samples::mp3(), &mut r).unwrap();
    assert!(has(&r, "ID3 tags (title, artist, comment, cover picture)") && has(&r, "ID3v1") && has(&r, "APE tag"), "{r:?}");
    assert!(out.starts_with(&[0xFF, 0xFB]) && out.len() == 2 * 417);
    no_secret(&out);

    let mut r = vec![];
    let out = clean(Kind::Flac, &samples::flac(), &mut r).unwrap();
    assert!(has(&r, "Tags (ARTIST, LOCATION)") && has(&r, "Cover picture"), "{r:?}");
    no_secret(&out);
    assert_eq!(&out[..4], b"fLaC");
    assert_eq!(out[4], 0, "STREAMINFO first, not last");
    assert_eq!(out[4 + 4 + 34], 0x83, "the seek table is the last block now");
    assert!(out.ends_with(&[0xFF, 0xF8, 0x69, 0x08, 0, 0, 0, 0]));

    let mut r = vec![];
    let out = clean(Kind::Wav, &samples::wav(), &mut r).unwrap();
    assert!(has(&r, "Broadcast extension") && has(&r, "Tags (INFO") && has(&r, "ID3 tags"), "{r:?}");
    no_secret(&out);
    assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize, out.len() - 8);
    assert!(out.windows(4).any(|w| w == b"data") && out.windows(4).any(|w| w == b"fmt "));
}

#[test]
fn kinds_are_read_from_content() {
    let k = |d: &[u8]| kind(d, || zip_kind_of(&d.to_vec()), false);
    assert_eq!(k(&samples::jpeg()), Some(Kind::Jpeg));
    assert_eq!(k(&samples::png()), Some(Kind::Png));
    assert_eq!(k(&samples::webp()), Some(Kind::Webp));
    assert_eq!(k(&samples::tiff()), Some(Kind::Tiff));
    assert_eq!(k(&samples::heic()), Some(Kind::Heif));
    assert_eq!(k(&samples::pdf(false)), Some(Kind::Pdf));
    assert_eq!(k(&samples::docx(false)), Some(Kind::Office));
    assert_eq!(k(&samples::odt(false)), Some(Kind::OpenDocument));
    assert_eq!(k(&samples::plain_zip()), Some(Kind::Zip));
    assert_eq!(k(&samples::mp3()), Some(Kind::Mp3));
    assert_eq!(k(&samples::flac()), Some(Kind::Flac));
    assert_eq!(k(&samples::wav()), Some(Kind::Wav));
    assert_eq!(k(b"just text"), None);
    assert_eq!(kind(b"\0\0\0\x18ftypisom\0\0\0\0", || None, true), Some(Kind::Media("mp4")));
    assert_eq!(kind(b"\0\0\0\x18ftypisom\0\0\0\0", || None, false), None, "without ffmpeg");
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("heimdall-strip-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn the_copy_never_replaces_anything_and_the_original_stays() {
    let d = scratch("names");
    let input = d.join("holiday.jpg");
    let jpeg = samples::jpeg();
    std::fs::write(&input, &jpeg).unwrap();
    std::fs::write(d.join("holiday (clean).jpg"), b"someone else's").unwrap();
    let o = run(&input, None, false).unwrap();
    assert_eq!(o.wrote.as_deref(), Some(d.join("holiday (clean 2).jpg").as_path()));
    assert_eq!(std::fs::read(&input).unwrap(), jpeg, "the original is unchanged");
    assert_eq!(std::fs::read(d.join("holiday (clean).jpg")).unwrap(), b"someone else's");
    assert!(run(&input, Some(&d.join("holiday (clean).jpg")), false).unwrap_err().contains("exists"));
    assert!(run(&input, Some(&input), false).is_err(), "never over the original");
    // a dry run writes nothing
    let o = run(&input, Some(&d.join("dry.jpg")), true).unwrap();
    assert!(o.wrote.is_none() && !o.removed.is_empty() && !d.join("dry.jpg").exists());
    // nothing hidden: no copy
    let clean_one = d.join("holiday (clean 2).jpg");
    let o = run(&clean_one, Some(&d.join("again.jpg")), false).unwrap();
    assert!(o.wrote.is_none() && o.removed.is_empty());
    // no temporary file is left behind
    let names: Vec<String> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert!(!names.iter().any(|n| n.contains("heimdall-strip")), "{names:?}");
    let _ = std::fs::remove_dir_all(&d);
}

fn tool(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

/// With ffmpeg here: a real picture with the made-up metadata still decodes after cleaning, and exiftool (when here too) finds
/// no GPS in it.
#[test]
fn a_real_jpeg_still_decodes() {
    if !tool("ffmpeg") {
        eprintln!("ffmpeg is not installed: skipped");
        return;
    }
    let d = scratch("real-jpeg");
    let plain = d.join("plain.jpg");
    let st = std::process::Command::new("ffmpeg")
        .args(["-nostdin", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=32x32:rate=1", "-frames:v", "1"])
        .arg(&plain)
        .status()
        .unwrap();
    assert!(st.success());
    let mut j = std::fs::read(&plain).unwrap();
    let segs = samples::jpeg_segments();
    j.splice(2..2, segs);
    let input = d.join("tagged.jpg");
    std::fs::write(&input, &j).unwrap();
    let o = run(&input, None, false).unwrap();
    let out = o.wrote.unwrap();
    let st = std::process::Command::new("ffmpeg")
        .args(["-nostdin", "-loglevel", "error", "-i"])
        .arg(&out)
        .args(["-f", "null", "-"])
        .status()
        .unwrap();
    assert!(st.success(), "the cleaned picture decodes");
    if tool("exiftool") {
        let o = std::process::Command::new("exiftool").arg("-a").arg("-G1").arg(&out).output().unwrap();
        let text = String::from_utf8_lossy(&o.stdout);
        assert!(!text.contains("GPS") && !text.contains("FakeCam") && !text.contains("Jane Roe"), "{text}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// With ffmpeg here: a video with a location (©xyz) and a title loses both; its picture is copied, not encoded again.
#[test]
fn video_loses_its_location() {
    if !media::available() {
        eprintln!("ffmpeg/ffprobe are not installed: skipped");
        return;
    }
    let d = scratch("video");
    let input = d.join("clip.mp4");
    let st = std::process::Command::new("ffmpeg")
        .args(["-nostdin", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=32x32:rate=5:duration=1", "-c:v", "mpeg4"])
        .args(["-metadata", "location=+48.8584+002.2945/", "-metadata", "title=Secret place"])
        .arg(&input)
        .status()
        .unwrap();
    assert!(st.success());
    let o = run(&input, None, false).unwrap();
    assert!(has(&o.removed, "Location") && has(&o.removed, "Title"), "{:?}", o.removed);
    let out = o.wrote.unwrap();
    let p = std::process::Command::new("ffprobe")
        .args(["-v", "error", "-show_format", "-show_streams", "-of", "json"])
        .arg(&out)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&p.stdout);
    assert!(!text.contains("48.8584") && !text.contains("Secret"), "{text}");
    assert!(text.contains("mpeg4"), "the same picture stream");
    let _ = std::fs::remove_dir_all(&d);
}
