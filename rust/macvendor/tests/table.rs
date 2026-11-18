//! The table on made-up registry files: every name and prefix below is invented (no real company's block), private addresses
//! are locally administered ones (02:...).

use heimdall_macvendor::{parse_mac, Answer, Builder, DataPaths, Registry, Table};
use std::path::PathBuf;

/// A text list in hwdata's layout (oui.txt), with a 24-bit block registered to the IEEE that holds smaller blocks.
const OUI_TXT: &str = "OUI/MA-L\t\t\tOrganization\ncompany_id\t\t\tOrganization\n\t\t\t\tAddress\n\n\
0C-00-01   (hex)\t\tEXAMPLE NETWORKS CORP\n\
0C0001     (base 16)\t\tEXAMPLE NETWORKS CORP\n\
\t\t\t\t1 Example Road\n\t\t\t\tSomewhere\n\n\
0C-00-02   (hex)\t\tSample Radio Co.,Ltd\n\
0C0002     (base 16)\t\tSample Radio Co.,Ltd\n\n\
0C-00-03   (hex)\t\tIEEE Registration Authority\n\
0C0003     (base 16)\t\tIEEE Registration Authority\n\n\
0C-00-01   (hex)\t\tA Second Claim On The Same Prefix\n";

/// hwdata's iab.txt layout: spaces, not tabs, and "(hex)" far to the right.
const IAB_TXT: &str = "OUI                                                         Organization\n\
IAB Range                                                   Organization\n\
                                                            Address\n\n\
0C-00-03                      (hex)                         Tiny Sensors Inc.\n\
ABC000-ABCFFF                 (base 16)                     Tiny Sensors Inc.\n\
                                                            Somewhere\n";

/// The IEEE's CSV layout, with CRLF line ends, a BOM, quoted names with commas and doubled quotes, and a line break inside an
/// address.
const MAM_CSV: &[u8] = b"\xef\xbb\xbfRegistry,Assignment,Organization Name,Organization Address\r\n\
MA-M,0C00030,\"Middle Block Devices, Inc.\",\"1 Way\r\nTown\"\r\n\
MA-M,0C00031,\"The \"\"Quoted\"\" Company\",Somewhere\r\n";

const OUI36_CSV: &str = "Registry,Assignment,Organization Name,Organization Address\n\
MA-S,0C0003ABD,Smallest Things GmbH,Somewhere\n\
MA-S,0C0003ABC,Shadowed By The IAB Block,Somewhere\n";

fn table(files: &[(&[u8], Registry)]) -> Table {
    let mut b = Builder::new();
    for (data, reg) in files {
        b.read(*data, *reg);
    }
    b.finish()
}

fn mac(s: &str) -> [u8; 6] {
    parse_mac(s).unwrap()
}

#[test]
fn the_longest_block_wins() {
    let t = table(&[
        (IAB_TXT.as_bytes(), Registry::Iab),
        (OUI36_CSV.as_bytes(), Registry::MaS),
        (MAM_CSV, Registry::MaM),
        (OUI_TXT.as_bytes(), Registry::MaL),
    ]);
    let v = |s: &str| t.lookup(&mac(s)).vendor().map(|v| (v.short, v.registry, v.bits));
    assert_eq!(v("0c:00:01:12:34:56"), Some(("Example Networks", Registry::MaL, 24)));
    assert_eq!(v("0c:00:02:12:34:56"), Some(("Sample Radio", Registry::MaL, 24)));
    // 36 bits (IAB, read first, keeps 0C-00-03-AB-C over the MA-S file's same prefix), then 36 (MA-S), 28 (MA-M), 24
    assert_eq!(v("0c:00:03:ab:c1:23"), Some(("Tiny Sensors", Registry::Iab, 36)));
    assert_eq!(v("0c:00:03:ab:d1:23"), Some(("Smallest Things", Registry::MaS, 36)));
    assert_eq!(v("0c:00:03:01:23:45"), Some(("Middle Block Devices", Registry::MaM, 28)));
    assert_eq!(v("0c:00:03:12:34:56"), Some(("The \"Quoted\" Company", Registry::MaM, 28)));
    assert_eq!(v("0c:00:03:ab:e1:23"), Some(("IEEE Registration Authority", Registry::MaL, 24)));
    let full = t.lookup(&mac("0c:00:03:01:00:00")).vendor().unwrap().name;
    assert_eq!(full, "Middle Block Devices, Inc.");
    // the first claim on a prefix stays
    assert_eq!(t.lookup(&mac("0c:00:01:00:00:00")).vendor().unwrap().name, "EXAMPLE NETWORKS CORP");
    assert_eq!(t.lookup(&mac("0c:00:04:00:00:00")), Answer::Unknown);
    assert_eq!(t.lookup_oui([0x0c, 0x00, 0x02]).unwrap().short, "Sample Radio");
    assert_eq!(t.lookup_oui([0x0c, 0x00, 0x04]), None);
    // the second claim on 0C-00-01 and the MA-S block under the IAB one are gone
    assert_eq!(t.len(), 7);
    assert_eq!(t.counts(), vec![(Registry::MaL, 24, 3), (Registry::MaM, 28, 2), (Registry::MaS, 36, 1), (Registry::Iab, 36, 1)]);
}

#[test]
fn addresses_that_say_what_they_are() {
    let t = table(&[(OUI_TXT.as_bytes(), Registry::MaL)]);
    let k = |s: &str| t.lookup_str(s).kind();
    let l = |s: &str| t.lookup_str(s).label();
    assert_eq!((k("ff:ff:ff:ff:ff:ff"), l("ff:ff:ff:ff:ff:ff")), ("special", "Broadcast"));
    assert_eq!(l("01:00:5e:00:00:fb"), "IPv4 multicast");
    assert_eq!(l("33:33:00:00:00:fb"), "IPv6 multicast");
    assert_eq!(l("01:80:c2:00:00:0e"), "LLDP");
    assert_eq!(l("00:00:5e:00:01:07"), "VRRP router");
    assert_eq!(l("00:00:5e:00:53:01"), "Documentation");
    assert_eq!(l("00:00:00:00:00:00"), "No address");
    assert_eq!((k("0d:00:01:00:00:01"), l("0d:00:01:00:00:01")), ("multicast", ""));
    // a group address in a registered block is still a group address
    assert_eq!(k("0d:00:01:00:00:00"), "multicast");
    // locally administered: private, even where the prefix (with the bit cleared) is registered
    for m in ["02:00:00:00:00:01", "0e:00:01:00:00:01", "da:00:00:00:00:01", "06:aa:bb:cc:dd:ee"] {
        assert_eq!(t.lookup_str(m), Answer::Private, "{m}");
    }
    for m in ["", "0", "zz:zz:zz:00:00:00", "0c:00:01:00:00", "0c:00:01:00:00:00:00", "0c-00:01:00:00:00"] {
        assert_eq!(t.lookup_str(m), Answer::Invalid, "{m}");
    }
}

#[test]
fn damaged_and_odd_files() {
    // lines that only look like blocks
    let bad = "0C-00-0G   (hex)\t\tNot Hex\n\
        0C-00   (hex)\t\tToo Short\n\
        0C:00:05   (hex)\t\tWrong Separator\n\
        0C-00-06   (hex)\t\t   \n\
        0C-00-07   (base 16)\t\tA Range Without Its Block\n\
        x 0C-00-08   (hex)\t\tSomething In Front\n\
        0C-00-09   (hex)\t\tBlock\n\
        000000-FFFFFF     (base 16)\t\tA Range As Big As The Block\n\
        0C-00-0A   (hex)\t\tAnother\n\
        000001-001000     (base 16)\t\tAn Unaligned Range\n";
    let t = table(&[(bad.as_bytes(), Registry::MaL)]);
    assert_eq!(t.len(), 2);
    assert_eq!(t.lookup_str("0c:00:09:00:00:01").vendor().unwrap().bits, 24);
    assert_eq!(t.lookup_str("0c:00:0a:00:00:01").vendor().unwrap().bits, 24);
    // names with control, invisible and direction-changing characters, and bytes that are not UTF-8
    let names = b"0C-00-0B   (hex)\t\tGood\xe2\x80\xae Name\x07\n0C-00-0C   (hex)\t\t\xc9cole\n";
    let t = table(&[(names, Registry::MaL)]);
    assert_eq!(t.lookup_str("0c:00:0b:00:00:01").vendor().unwrap().name, "Good Name");
    assert_eq!(t.lookup_str("0c:00:0c:00:00:01").vendor().unwrap().name, "\u{fffd}cole");
    // CSV rows that are not blocks
    let csv = "Registry,Assignment,Organization Name\n\
        CID,0C0001,A Company ID\n\
        MA-L,0C001,Five Digits\n\
        MA-L,0C00010C00010,Thirteen Digits\n\
        MA-L,0C00XY,Not Hex\n\
        MA-L,0C000D\n\
        MA-L,0C000E,\n\
        MA-L, 0C000F ,Spaces Around\n\
        ma-l,0c0010,Lower Case\n\
        MA-L,0C0011,\"Unclosed quote\n";
    let t = table(&[(csv.as_bytes(), Registry::MaL)]);
    assert_eq!(t.len(), 2);
    assert_eq!(t.lookup_str("0c:00:0f:00:00:01").label(), "Spaces Around");
    assert_eq!(t.lookup_str("0c:00:10:00:00:01").label(), "Lower Case");
    // an unclosed quote swallows at most a record's worth of lines, then reading goes on
    let mut long = String::from("Registry,Assignment,Organization Name\nMA-L,0C0012,\"open\n");
    for _ in 0..400 {
        long.push_str("filler line inside the quote, about fifty bytes.\n");
    }
    long.push_str("MA-L,0C0013,After The Damage\n");
    let t = table(&[(long.as_bytes(), Registry::MaL)]);
    assert_eq!(t.lookup_str("0c:00:13:00:00:01").label(), "After The Damage");
    // empty input, only a header, only a BOM
    for empty in [&b""[..], b"\n\n", b"Registry,Assignment,Organization Name\r\n", b"\xef\xbb\xbf", b"OUI/MA-L\n"] {
        let t = table(&[(empty, Registry::MaL)]);
        assert!(t.is_empty());
        assert_eq!(t.lookup_str("0c:00:01:00:00:01"), Answer::Unknown);
    }
}

fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("macvendor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("ieee")).unwrap();
    std::fs::create_dir_all(d.join("hwdata")).unwrap();
    d
}

#[test]
fn loading_prefers_the_ieee_files_and_falls_back_to_hwdata() {
    let d = temp("load");
    let paths = DataPaths { ieee_dir: d.join("ieee"), hwdata_dir: d.join("hwdata") };
    // nothing at all: an empty table, every maker unknown
    assert!(Table::load(&paths).is_empty());
    std::fs::write(d.join("hwdata/oui.txt"), OUI_TXT).unwrap();
    std::fs::write(d.join("hwdata/iab.txt"), IAB_TXT).unwrap();
    let t = Table::load(&paths);
    assert_eq!(t.lookup_str("0c:00:01:00:00:01").vendor().unwrap().short, "Example Networks");
    assert_eq!(t.lookup_str("0c:00:03:ab:c0:01").vendor().unwrap().registry, Registry::Iab);
    // the IEEE's files, when there, replace hwdata's for their registry; MA-M and MA-S exist only there
    std::fs::write(d.join("ieee/oui.csv"), "Registry,Assignment,Organization Name\nMA-L,0C0001,Fresher Name Ltd\n").unwrap();
    std::fs::write(d.join("ieee/mam.csv"), MAM_CSV).unwrap();
    std::fs::write(d.join("ieee/oui36.csv"), OUI36_CSV).unwrap();
    let t = Table::load(&paths);
    assert_eq!(t.lookup_str("0c:00:01:00:00:01").label(), "Fresher Name");
    assert_eq!(t.lookup_str("0c:00:02:00:00:01"), Answer::Unknown);
    assert_eq!(t.lookup_str("0c:00:03:01:00:01").vendor().unwrap().registry, Registry::MaM);
    assert_eq!(t.lookup_str("0c:00:03:ab:d0:01").vendor().unwrap().registry, Registry::MaS);
    // the MA-S file is read before the IAB list: the shared prefix is the MA-S file's
    assert_eq!(t.lookup_str("0c:00:03:ab:c0:01").vendor().unwrap().registry, Registry::MaS);
    // a damaged download (no block in it) falls back to hwdata
    std::fs::write(d.join("ieee/oui.csv"), "<html>not found</html>\n").unwrap();
    assert_eq!(Table::load(&paths).lookup_str("0c:00:02:00:00:01").label(), "Sample Radio");
    // a folder in place of a file is skipped
    std::fs::remove_file(d.join("ieee/oui.csv")).unwrap();
    std::fs::create_dir(d.join("ieee/oui.csv")).unwrap();
    assert_eq!(Table::load(&paths).lookup_str("0c:00:02:00:00:01").label(), "Sample Radio");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_fifo_is_not_waited_on() {
    let d = temp("fifo");
    let fifo = d.join("ieee/oui.csv");
    // (std has no mkfifo; the coreutils program makes it)
    let made = std::process::Command::new("mkfifo").arg(&fifo).status().map(|s| s.success()).unwrap_or(false);
    if made {
        let paths = DataPaths { ieee_dir: d.join("ieee"), hwdata_dir: d.join("hwdata") };
        assert!(Table::load(&paths).is_empty());
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The real lists, where hwdata is installed: every block is read and a lookup finds the right size.
#[test]
fn hwdata_when_installed() {
    let paths = DataPaths { ieee_dir: PathBuf::from("/nonexistent"), ..DataPaths::default() };
    if !paths.hwdata_dir.join("oui.txt").exists() {
        return;
    }
    let t = Table::load(&paths);
    let counts = t.counts();
    let mal = counts.iter().find(|c| c.0 == Registry::MaL).map_or(0, |c| c.2);
    assert!(mal > 30000, "{counts:?}");
    if paths.hwdata_dir.join("iab.txt").exists() {
        assert!(counts.iter().any(|c| c.0 == Registry::Iab && c.1 == 36 && c.2 > 4000), "{counts:?}");
    }
}
