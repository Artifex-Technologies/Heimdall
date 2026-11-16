# The privacy pack

I want people who use Labyrinth OS (and LykanOS) to be safe by default from files that give them away. A file can do that
in two ways: when it is **opened** it can call a server (a "tracking pixel" in a Word document, a PDF that opens a web
address by itself), which tells that server the file was opened, when, and from which address; and when it is **shared**
it can carry hidden information (the GPS position of a photo, the author and company of a document). The pack has four
parts; all four are on by default, each with its own switch in Settings > Security > Privacy.

| Part | Where | Switch (Settings > Security > Privacy) |
| --- | --- | --- |
| The downloads guard: a notice when a downloaded file would contact a server when opened | Heimdall: `heimdall-fileguard` (a user service) | Check downloads |
| Remove hidden info: a clean copy of a photo, video, song or document | Heimdall: `heimdall-strip`; Minos' right-click menu | Remove hidden info in Minos |
| Viewer apps ask before going online the first time | Labyrinth OS: `labyrinth-appnet` (its docs/PRIVACY_PACK.md) | Viewer apps ask before going online |
| Look-alike names: a warning on names that imitate others ("Vivаldi" with a Cyrillic а) | the same small module in Heimdall, Labyrinth OS and Yggdrasil | Warn about look-alike names |

Parts 1, 2 and the look-alike module are this repository's (`rust/privacy`, the crate `heimdall-privacy`); they come in the
package `heimdall-private-mic-git` with the private microphone, which every Labyrinth OS and LykanOS install has, with or
without Heimdall (`packaging/install.sh DESTDIR private-mic`).

## The switches file

`~/.config/heimdall/privacy.json` (`$XDG_CONFIG_HOME/heimdall/privacy.json`), one per person:

```json
{"downloads_guard": true, "remove_hidden_info": true, "lookalike_warnings": true}
```

Settings writes it (keeping any other keys; temporary file and rename). The downloads guard, Minos, Agora, Settings > Apps and
Labyrinth's network question read it. A missing file, a missing key or a value that is not `true` or `false` counts as **on**.
The fourth switch (viewer apps) is Labyrinth's own, kept by `labyrinth-appnet` (root's), not here.

## 1. The downloads guard (`heimdall-fileguard`)

A user service, `heimdall-fileguard.service` (on for every account through `graphical-session.target.wants`), watches with
inotify:

- the desktop's download folder (`XDG_DOWNLOAD_DIR` in `~/.config/user-dirs.dirs`, else `~/Downloads`);
- the torrent clients' folders: Deluge (`download_location`, and `move_completed_path` when moving is on, from
  `~/.config/deluge/core.conf`), qBittorrent (`Session\DefaultSavePath`, older `Downloads\SavePath`), Transmission
  (`download-dir`, also of transmission-daemon), each also as its Flatpak;
- any folder in `~/.config/heimdall/fileguard.json`: `{"folders": ["~/Torrents", "/mnt/data/incoming"]}`.

Sub-folders are watched too (four levels, 4096 watches at most). Never `/`, a system folder or the whole home. The settings
files are watched as well, so a folder changed in a torrent client, or the switch moved in Settings, is followed within a
second; the folders are also read again every five minutes (a drive mounted later).

**When a file is finished.** A file is checked when it was closed after writing (`IN_CLOSE_WRITE`) or arrived by rename
(`IN_MOVED_TO`: a browser renaming `.part` to the real name, a torrent client moving a finished file), and then nothing
happened to it for a second. Partial files are never checked: `.part`, `.crdownload`, `.download`, `.!qB`, `.!ut`, `.!bt`,
`.partial`, `.aria2`, `.filepart`, `.unconfirmed`, `.incomplete`, Chrome's `.com.google.Chrome.*`, office lock files. A
finished torrent's folder moved in has its files checked. Each file is checked once per size and change time.

**What is checked** (from the content; the name only for text formats):

| Kind | Found |
| --- | --- |
| Office (Word, Excel, PowerPoint) | external relationships (`TargetMode="External"`) of kind template (`attachedTemplate`), picture, OLE object, frame, sub-document, media, font; links to workbooks on a server (Excel asks first: "can"); Word fields `INCLUDEPICTURE`, `INCLUDETEXT`, `LINK` with a server address, also when the field's code is split over several runs; Excel web data connections (`refreshOnLoad`: by itself) |
| OpenDocument | linked pictures, objects, frames, templates (`meta:template`), sections and table data on a server (LibreOffice asks first: "can"), DDE links |
| PDF | what runs by itself: the catalogue's `/OpenAction` and every `/AA` (page open and close, a field's format and calculation, hover), followed through `/Next` chains, for actions that reach outside: `URI`, `SubmitForm`, `ImportData`, `GoToR`/`GoToE` with a server address, `Launch`, `JavaScript`, `Rendition`/`Sound`/`Movie` with a server address; and JavaScript or a Launch action anywhere ("can"). A clickable link is not reported. Names written with `#xx` escapes are read decoded; object streams are unpacked in memory |
| SVG, HTML | every attribute that loads when shown (`src`, `href` but on `<a>`, `srcset`, `poster`, `data`, `background`...), CSS `url(...)` and `@import` (style elements and attributes), `<meta http-equiv="refresh">` to a server, `<base href>`, `<?xml-stylesheet?>`, an outside DTD or entity ("can"), scripts and `on...` handlers ("can"); entities and the tabs and line breaks browsers ignore are decoded first (`h&#116;tp:`) |
| Playlists | M3U/M3U8 entries and `URI="..."` attributes (HLS keys, maps), PLS `FileN=`, XSPF `<location>` and `<image>`, ASX `<ref>`, `<entryref>`, `<logo>`, `<banner>`: any entry on a server |
| Shortcuts | `.desktop` of type Link with a server address, any `.desktop` launcher ("can": it runs a command), a remote icon; `.url`/`.website`/`.scf` with a server address or an icon on a network share (Windows fetches that icon as soon as the folder is shown); `.webloc` |
| Archives | ZIP: the files in it that can contact a server are checked in memory (documents, PDFs, SVG, HTML, playlists, shortcuts), one level deep, never extracted; a shortcut or playlist that cannot be read is reported by its name. tar (also compressed), 7z, rar: the list of names (bsdtar, in a bubblewrap sandbox without network when bwrap is installed, 30 s of processor time and 1 GiB at most), shortcuts and playlists reported by name |

"A server" is any address with a network scheme (`http:`, `https:`, `ftp:`, `smb:`, `mms:`, `rtsp:`, any unknown
`scheme:`), a protocol-relative `//host/`, a network share (`\\server\share`, `file://server/`). Local paths, `data:`,
`file:///`, fragments, `mailto:` are not.

**The notice** (desktop notification, from Heimdall): the title is "This file tries to contact a server when opened." (when
something would do it by itself) or "This file has parts that can contact a server." (scripts, things the program asks about
first). The text names the file (control, invisible and direction-changing characters written as `<U+202E>`, so a name
cannot turn itself around; with a look-alike warning when it imitates another and that switch is on), the first finding and
how many more, and "It was not changed." Buttons:

- **Show details**: a page (Markdown, private, in the runtime folder) with every finding and address, opened in Saga MD
  (else the default program for Markdown).
- **Show in Minos**: the file's folder in Minos (Minos opens a folder; it cannot select one file yet).
- **Dismiss**.

There is **no "Open offline in Limbo"**: I checked Limbo's commands and docs on 2026-11-15, and it has no way to open a
document without network on the desktop. `limbo wine` is for Windows programs (off the network by default, but a Linux PDF
viewer does not run in it) and `limbo analyze` is root's sealed analysis of a sample for Heimdall's quarantine, not a viewer.
When Limbo gets one, the notice can offer it.

**It never changes a file**: not the content, not its time, not its name, not its place. A torrent keeps seeding and a
signature stays valid. At most three notices are open at a time; the rest are written to the journal only.

**Running light.** One thread, asleep in `poll()` while nothing happens (no timer while nothing waits; a wake-up every five
minutes to read the folders again), at nice 10 and idle I/O priority, memory capped at 512 MiB by its unit; it opens no
network connection (`RestrictAddressFamilies=AF_UNIX`).

**Commands.**

```text
heimdall-fileguard check [--json] FILE...   exit 0: nothing found, 1: something found, 2: a file could not be read
heimdall-fileguard watch                    the service
heimdall-fileguard folders                  the folders it watches
heimdall-fileguard status --json            {"enabled":bool,"running":bool,"folders":[...]}
```

`check --json` prints one line per file: `{"path","kind","found","complete","notes","findings":[{"sure","what","target",
"inside"}],"name_warning"}`.

## 2. Remove hidden info (`heimdall-strip`, Minos)

Minos' right-click menu (Privacy, beside "Scrub location sounds") has **Remove hidden info** for a single local file of a kind
it cleans, when `heimdall-strip` is installed and the switch is on. It writes a copy, "name (clean).ext" beside the original
(then "name (clean 2).ext"...), and shows what was removed. The original is never changed. The copy is written under a
hidden temporary name and linked into place only where nothing is, so it never replaces a file.

| Kind | Removed | Kept |
| --- | --- | --- |
| JPEG | EXIF (GPS, camera make and model, serial numbers, dates, software, maker notes, thumbnail), XMP and extended XMP, Photoshop/IPTC (captions, places, names), comments, JFXX thumbnails, MPF and other APPn data, anything after the picture (a second picture, a depth map) | JFIF, the ICC colour profile, Adobe's colour transform, the orientation (a tiny EXIF with only that tag, so a phone photo does not turn on its side) |
| PNG | tEXt/zTXt/iTXt (XMP included), eXIf, tIME, private chunks | the picture and colour chunks, APNG frames, the orientation |
| WebP | EXIF, XMP, unknown chunks (the VP8X flags follow) | the picture, ICC, animation, the orientation |
| HEIC/HEIF/AVIF | the Exif and XMP items, written over in place (an empty EXIF, an empty XMP packet) so no offset moves | everything else, byte for byte |
| TIFF | every tag but the picture's own (make, model, artist, software, dates, EXIF, GPS, XMP, IPTC, Photoshop); written anew | the picture data and the tags that describe it, ICC |
| PDF | the document information (/Info: author, producer, dates, title...), XMP streams and every /Metadata pointer, /PieceInfo, /LastModified, the document id; written anew with a plain cross-reference table, then read back (and opened with poppler's pdfinfo where installed) before it is kept | every page, font, picture and form |
| Office | docProps/core.xml (author, last modified by, revision, dates, title...), app.xml (company, manager, template name, editing time, program), custom.xml; Word's attached template path (it can hold the user name) and rsid list; Excel's saved-in folder (`x15ac:absPath`) | the content; unchanged parts are copied as they were compressed |
| OpenDocument | meta.xml (author, dates, editing cycles and time, generator, template, printed by, custom properties), the printer name and setup in settings.xml | the content; `mimetype` first and stored, as the format requires |
| ZIP | archive and file comments, extra fields (exact times, owner ids), times (all 1980-01-01), owners and permissions (644/755) | the files, as they were compressed |
| MP3 | ID3v2 (at the start or end), ID3v1, APE, Lyrics3 | the frames, byte for byte (the encoder's frame for gapless playback included) |
| FLAC | Vorbis comments, pictures, application data, cue sheets, padding, an ID3 tag before it | STREAMINFO, the seek table, the frames |
| WAV | LIST/INFO, marker labels, bext (originator, date and time, history), iXML, id3, XMP, private chunks | fmt, fact, cue, smpl, inst, data |
| MP4, MOV, M4A, 3GP, MKV, WebM, Ogg, Opus, AVI, ASF | with ffmpeg (argv, `file:` before each path, `-c copy`: nothing is encoded again): every tag (the location a phone writes, `©xyz` and `com.apple.quicktime.location.ISO6709`, dates, device, software, titles), chapters, data tracks (a camera's GPS track); ffprobe says first what was there | the picture, sound and subtitle streams, and their languages |

Encrypted PDFs and ZIP files are not changed (the tool says so). Camera raw files (TIFF with sub-pictures), BigTIFF, old-style
JPEG in TIFF, RF64 and items stored inside a HEIF's own box are refused with a message, never half-cleaned.

```text
heimdall-strip [--json] IN [OUT]     the copy; prints "removed: ..." lines then "wrote OUT" (or one JSON line)
heimdall-strip --check [--json] IN   what would be removed; writes nothing
heimdall-strip --can IN              exit 0 and print the kind when IN can be cleaned, 1 when not
```

`--json`: `{"wrote": "/path" | null, "removed": ["GPS position (EXIF)", ...], "kind": "jpeg"}`. `wrote` is null and
`removed` empty when nothing hidden was found: then no copy is made. Exit codes: 0 done, 1 failed (the last line on standard
error is `heimdall-strip: MESSAGE`), 2 usage. Minos runs `--can` (when its menu opens on a file, on a thread, 3 s at most) and
`--json IN OUT`. Changing these outputs is a contract change for Yggdrasil too.

## 4. Look-alike names (`lookalike.rs`)

The same file in three repositories, so each place that shows a name decides the same way: here
`rust/privacy/src/lookalike.rs` (the original), Labyrinth OS `packages/tools/src/lookalike.rs`, Yggdrasil
`packages/yggdrasil-ui/src/lookalike.rs`. Change it here first and copy it (tests included).

It follows Unicode TR39 in a small form: a script per character (the blocks that matter), the "highly restrictive" mixing rule
(one script, or Latin with the Chinese, Japanese and Korean combinations), and a skeleton from a short table of the
confusables that imitate ASCII (Cyrillic, Greek, Armenian, Cherokee look-alikes, Latin's own deceptive letters such as the
dotless i, fullwidth and mathematical letters, Roman numerals, the Kelvin sign). A name is flagged when it mixes alphabets,
when letters only look like ASCII ones (with the name it imitates), or when it has invisible, direction-changing or control
characters. A plain ASCII name is never flagged; real names in one alphabet ("Блокнот", "メモ帳", "Café") are not either.

Where it is used: the downloads guard's notice and details (the file name), Labyrinth's network question (the app's name,
its program, the host name of the address), Settings > Apps (an app's name, with the program it really starts), and Agora's
listings (with what the listing really is: package, AUR package, Flatpak id). Each shows a badge or warning and the real
thing, never hides the name.

## Tests and fuzzing

`cd rust && cargo test -p heimdall-privacy` (all offline; no test sends anything anywhere):

- made-up files (`src/samples.rs`): a Word document with a template on a server, an OpenDocument text with a linked picture,
  PDFs with an `/OpenAction`, chained `/AA` actions, `#xx`-escaped names, JavaScript, Launch; SVG, HTML, all four playlist
  kinds, shortcuts; pictures, songs and documents with a fake GPS position (the Eiffel Tower's public coordinates), a fake
  camera, a fake author ("Jane Roe") and company ("Example Corp"). Every server is an `example.com/.net/.org` name.
- what must be found is found, what must not (clickable links, local templates, a page-turning `/OpenAction`) is not; each
  cleaner removes what it says and nothing of the content, and a cleaned file cleaned again has nothing left to remove.
- where the programs are installed: a real JPEG made by ffmpeg still decodes after cleaning and exiftool finds no GPS, camera
  or author in it; a real MP4 with a location and a title loses both while its video stream is copied; a real tar is listed
  by bsdtar. Without them those tests say so and pass.
- the commands (`tests/cli.rs`): arguments, output and exit codes as Minos and Settings use them; never over a file.
- caps: a 32 MiB part packed into a few kilobytes (a ZIP bomb) is not unpacked; nesting stops at a limit; a TIFF whose
  strips all point at the same bytes is refused.

**Fuzzing.** Six targets (`src/fuzzing.rs`): the guard under every file name, every cleaner (and its output cleaned again),
the ZIP reader, the PDF scanner, the markup reader, the look-alike check. `cargo +nightly fuzz run privacy_guard
seeds/privacy_guard` (and `privacy_strip`, `privacy_zip`, `privacy_pdf`, `privacy_markup`, `privacy_lookalike`) in
`rust/fuzz`. In the ordinary tests (`tests/fuzz_smoke.rs`) the same bodies run on the samples, on every cut-short version, on
mutated versions and on random bytes, and on every `crash-*` file in `rust/fuzz/seeds/privacy_*` (inputs that once broke
something). Where nightly is not at hand, the same mutator runs for as long as asked:

```bash
HEIMDALL_FUZZ_SECS=600 cargo test --release -p heimdall-privacy --test fuzz_smoke -- --ignored long_mutation_run --nocapture
```

On 2026-11-15 (no nightly toolchain on this machine) it ran about 12 million mutated inputs through all six targets and found
five bugs, all fixed and kept as `crash-*` seeds: a TIFF tag of an unknown type with a huge count made a 6.8 GB allocation; a
PDF dictionary cut short after its `/Length` key read past its tokens; a WebP cut inside its VP8X header indexed past it; a PDF
with one object numbered in the millions made a cross-reference table of hundreds of megabytes (now refused); a HEIF item
table claiming millions of entries spun for a second. After the last fixes, about 3.9 million inputs ran clean, the slowest
single call about 1 ms.

## Honest limits

- The guard sees files that land in the folders it watches. A file saved elsewhere, or opened straight from the browser
  without saving, is not checked. A torrent client writing in place without a temporary suffix closes the file only when it
  is done (or paused): a paused download can be checked half-written (it is checked again when it changes).
- It reports, it does not block: the person can still open the file. Formats not listed above are not looked into (an `.lnk`
  is reported by name inside archives only; EPUB, RTF, email files and Office 97 binary files are not read yet).
- Archives other than ZIP are listed, not opened: a document inside a 7z is not checked.
- Remove hidden info works on what the format holds as metadata. It does not remove what is in the content: a name typed in a
  document, comments and tracked changes (their authors stay: accept or remove them in the office app), a face or a street sign
  in a photo, Word's rsid attributes inside the text (only the settings' list goes), pictures' own metadata inside a PDF or an
  Office file, XMP inside fonts. A PDF over 1 GiB, an encrypted PDF or ZIP, and the refused kinds above are not cleaned.
- Look-alike detection uses a small table, not the whole confusables.txt: it catches what imitates ASCII letters and digits,
  not look-alikes between two non-Latin scripts.
