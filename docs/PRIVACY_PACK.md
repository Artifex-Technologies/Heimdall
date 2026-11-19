# The privacy pack

I want people who use Labyrinth OS (and LykanOS) to be safe by default from files that give them away. A file can do that
in two ways: when it is **opened** it can call a server (a "tracking pixel" in a Word document, a PDF that opens a web
address by itself), which tells that server the file was opened, when, and from which address; and when it is **shared**
it can carry hidden information (the GPS position of a photo, the author and company of a document). The pack has four
parts; all four are on by default, each with its own switch in Settings > Security > Privacy.

| Part | Where | Switch (Settings > Security > Privacy) |
| --- | --- | --- |
| The downloads guard: a notice when a downloaded file would contact a server when opened | Heimdall: `heimdall-fileguard` (a user service) | Check downloads |
| Safe file intake: every file I add is checked (`scan`), archives are unpacked safely (`extract`), new files in my own folders and drives are checked | Heimdall: `heimdall-fileguard scan`, `extract` (for any program to call; Settings' fonts page uses them) | Check new files in my folders (`folders_guard`) |
| Remove hidden info: a clean copy of a photo, video, song or document | Heimdall: `heimdall-strip`; Minos' right-click menu | Remove hidden info in Minos |
| Viewer apps ask before going online the first time | Labyrinth OS: `labyrinth-appnet` (its docs/PRIVACY_PACK.md) | Viewer apps ask before going online |
| Look-alike names: a warning on names that imitate others ("Vivаldi" with a Cyrillic а) | the same small module in Heimdall, Labyrinth OS and Yggdrasil | Warn about look-alike names |

Parts 1, 2 and the look-alike module are this repository's (`rust/privacy`, the crate `heimdall-privacy`); they come in the
package `heimdall-private-mic-git` with the private microphone, which every Labyrinth OS and LykanOS install has, with or
without Heimdall (`packaging/install.sh DESTDIR private-mic`).

## The switches file

`~/.config/heimdall/privacy.json` (`$XDG_CONFIG_HOME/heimdall/privacy.json`), one per person:

```json
{"downloads_guard": true, "folders_guard": true, "remove_hidden_info": true, "lookalike_warnings": true}
```

Settings writes it (keeping any other keys; temporary file and rename). The downloads guard, Minos, Agora, Settings > Apps and
Labyrinth's network question read it. A missing file, a missing key or a value that is not `true` or `false` counts as **on**.
`downloads_guard` switches the whole guard (off: nothing is watched); `folders_guard` (2026-11-18) only the watching of my own
folders (Desktop, Documents, Pictures, Music, Videos) and the notice when a drive is connected. `scan` and `extract` are asked
for by an app and always run: no switch turns them off.
The fourth switch (viewer apps) is Labyrinth's own, kept by `labyrinth-appnet` (root's), not here.

## 1. The downloads guard (`heimdall-fileguard`)

A user service, `heimdall-fileguard.service` (on for every account through `graphical-session.target.wants`), watches with
inotify:

- the desktop's download folder (`XDG_DOWNLOAD_DIR` in `~/.config/user-dirs.dirs`, else `~/Downloads`);
- the torrent clients' folders: Deluge (`download_location`, and `move_completed_path` when moving is on, from
  `~/.config/deluge/core.conf`), qBittorrent (`Session\DefaultSavePath`, older `Downloads\SavePath`), Transmission
  (`download-dir`, also of transmission-daemon), each also as its Flatpak;
- any folder in `~/.config/heimdall/fileguard.json`: `{"folders": ["~/Torrents", "/mnt/data/incoming"]}`;
- with `folders_guard` on (the default): Desktop, Documents, Pictures, Music and Videos (their `XDG_*_DIR`, else `~/Desktop`
  ...), so a file copied in from a USB drive, saved by an app or unpacked by hand is checked the same way, whatever brought it.

Sub-folders are watched too (four levels, 4096 watches at most, the download folders first). Never `/`, a system folder or the whole home. The settings
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
heimdall-fileguard scan [--json] FILE...    section 5
heimdall-fileguard scan-drive FOLDER        section 5 (what "Scan this drive" runs)
heimdall-fileguard extract [--json] [--only EXT,EXT] ARCHIVE OUTDIR   section 5
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

## 5. Safe file intake (`scan`, `extract`)

I decided on 2026-11-18 that files I add (fonts dropped into Settings, archives unpacked in Minos, files copied from a USB drive)
are checked by Heimdall whatever their origin, and that a decompression bomb ("ZIP bomb") must not hurt the system. It is the
same program, in the same package (`heimdall-private-mic-git`, on every Labyrinth OS and LykanOS install, with or without
Heimdall).

### `heimdall-fileguard scan [--json] FILE...`

The one "check this file before I use it". For each file:

| Check | Verdict |
| --- | --- |
| Its name: a look-alike, invisible, direction-changing or control character (section 4) | warn |
| What it really is: a program (Linux, Windows, macOS, or a `#!` script) named like a font, picture, song, video or document | refused |
| A font extension (`ttf otf ttc otc woff woff2 pfb pfa`) whose content is not a font | refused |
| The downloads guard's checks (section 1): something that contacts a server when opened | warn |
| An archive (ZIP, which Office and OpenDocument files are too, tar, compressed tar, a single `.gz/.xz/.zst/.bz2` file): `extract`'s dry run in its sandbox, nothing written, one level deep | bomb, a name that escapes, a file named two ways: refused; too big to check in full, damaged, two entries with one name: warn; encrypted parts: warn |
| ClamAV: `clamdscan` when the clamd daemon answers, else `clamscan`, else none | known malware: refused; possibly unwanted or a heuristic guess: warn; stopped at a limit: warn ("not fully scanned"); none: `unavailable` |

`--json` prints one document (the keys are a contract with Yggdrasil):

```json
{"files":[{"path":"/home/me/Inter.ttf","verdict":"ok","reasons":[],"clamav":"clean"}]}
```

`verdict` is `ok`, `warn` or `refused`; `reasons` are plain sentences, the most important first; `clamav` is `clean`,
`infected:SIGNATURE`, `unavailable` (no ClamAV, or it could not run) or `not-fully-scanned` (ClamAV stopped at a limit, or the
file is bigger than ClamAV's limits: the verdict is then at least `warn`, and a reason says so). Exit 0 when nothing is
refused, 1 when something is, 2 when a file could not be read (it is listed as `refused` with the reason) or the command was
wrong. The text form gives one line per file, its reasons under it, and "ClamAV: ...".

ClamAV gets the files as `/proc/self/fd/N` of descriptors this program opened: it scans the very file that was checked, and its
answer cannot be confused by a name with ": " or a line break in it. `HEIMDALL_CLAMAV=off|clamscan|clamdscan` forces a choice.

### ClamAV's limits

clamscan gets them on its command line (it does not read clamd.conf); clamd from `/etc/clamav/clamd.conf`, which Labyrinth OS
ships with the same values (`profile/airootfs/etc/clamav/clamd.conf`):

| Limit | Value | Why |
| --- | --- | --- |
| MaxFileSize | 256 MiB | as `extract`'s per-file limit; ClamAV cannot scan over 2 GB at all |
| MaxScanSize | 512 MiB | as `extract`'s total (an archive and what it unpacks to count together) |
| MaxRecursion | 12 | archives in archives; ClamAV's default is 17 |
| MaxFiles | 10,000 | as `extract`'s entry limit |
| MaxScanTime | 120 s | ClamAV's default, said explicitly |
| AlertExceedsMax | yes | ClamAV says "Heuristics.Limits.Exceeded.*" instead of a silent "OK" |

That name is never malware: `scan` calls it `not-fully-scanned` (a warning), Labyrinth's labyrinth-scan-downloads logs it as
NOT FULLY SCANNED without a notice, so a big legitimate archive is never quarantined for its size. Where clamd runs without
AlertExceedsMax (another distribution), `scan` compares the sizes with clamd's limits itself.

### `heimdall-fileguard extract [--json] [--only EXT,EXT] ARCHIVE OUTDIR`

Unpacks into OUTDIR, which must not exist: it is made, 0700. The formats: ZIP (stored and deflated entries, ZIP64), tar (ustar,
GNU long names, pax), tar compressed with gzip (in the program, flate2), xz, zstd or bzip2 (the system's `xz`, `zstd` and
`bzip2`, which every Arch install has, each with a memory limit of 256 MiB), and a single compressed file. 7z and RAR are not
opened ("Heimdall does not open 7z archives"). I looked at a pure-Rust xz reader (lzma-rs 0.3): it keeps a whole LZMA2 block in
memory before it hands out a byte, so the size could not be counted as it streams; the system's xz streams.

The limits, counted on the bytes really unpacked (a header that says less is caught on the first byte too many; a header that
admits to too much only makes the refusal come sooner):

| Limit | Value |
| --- | --- |
| Unpacked in all (for a compressed tar: the whole stream, files skipped by `--only` included) | 512 MiB |
| One file | 256 MiB (the kernel enforces it too: RLIMIT_FSIZE) |
| Entries | 10,000 |
| Growth of one file, and of the archive in all | 100 times, once a file has unpacked to 1 MiB and the archive to 4 MiB (small files compress well and are harmless) |
| Archives inside | written as files, never opened by `extract`; `scan` then looks into each once, one level deep |

Refused, the whole archive, before or while writing: a name that is absolute or climbs out with `..` ("zip slip", also when it
only becomes `..` once cleaned), files that share bytes (overlapping entries, quines), a file whose two headers give two
names, two entries with one name (or a file and a folder), a name over 255 bytes or 64 folders deep, damage (a checksum, a size
that does not match, a cut-short archive). Left out and listed in `skipped`: links, hard links, devices, FIFOs, sockets (never
made), encrypted entries (Heimdall cannot look inside), compression methods it does not read, and with `--only` every file of
another kind (`--only ttf,otf,ttc,woff2` for fonts; folders are then made only for the files kept). Names are cleaned: control
characters become `_`, invisible and direction-changing characters are removed. Files are written 0600, never runnable: a
program inside loses its run permission. Each file is then checked by `scan` (ClamAV included).

On any refusal, of the archive or of a file in it, everything written is removed, OUTDIR too, and `refused` says why in plain
words. `--json`:

```json
{"files":[{"name":"Inter/Inter.ttf","path":"/home/me/.cache/x/Inter/Inter.ttf","size":303616,"verdict":"ok","reasons":[],"clamav":"clean"}],
 "skipped":[{"name":"Inter/OFL.txt","reason":"not one of the kinds asked for (ttf, otf, ttc, woff2)"}],
 "refused":null}
```

`name` is the name in the archive (made safe to show), `path` where it was written. When `refused` is not null nothing is left on
disk; `files` then lists what was checked before the stop (a file `scan` refused names itself in `refused`: "NAME: reason").
Exit 0 done, 1 refused, 2 a usage or reading error (OUTDIR exists, the archive cannot be read; `--json` still prints the
document with `refused` saying why).

**The sandbox.** The unpacking runs in a process of its own (`heimdall-fileguard extract-worker`, the same program) that opens
the archive and OUTDIR, then shuts itself in with **Landlock**: it may create files and folders only inside OUTDIR, read and run
only what is under `/usr` (the decompressors), nothing else (not my home, not `/etc`); TCP is shut where the kernel's Landlock
knows networks (version 4), and signals and abstract sockets where it knows scopes (version 6). It also takes an empty network
namespace when the kernel allows it. The parent sets its limits before it starts: 1 GiB of memory (address space), 120 s of
processor time, 256 MiB per file, 64 open files, no core dump, and kills it after 300 s. A worker that dies of those limits is a
refusal ("the archive could not be unpacked safely"). I chose Landlock over bubblewrap: it is in the kernel (5.13 and later,
also on the Raspberry Pi), needs nothing installed and costs a few system calls, not a process of its own. Without it (an old
kernel) the unpacking runs under the limits and the namespace only, and says so on standard error. `scan` runs an archive's dry
run in the same worker.

### New files in my folders and drives

The guard's `watch` (section 1) now also watches Desktop, Documents, Pictures, Music and Videos (switch `folders_guard`), still
with inotify only. When a file arrives it gets the light checks at once (the guard's, its name, a program dressed as something
else: a notice "This file is not safe to use." when refused, with Show details, Show in Minos, Dismiss). The heavy part follows
(an archive's dry run; ClamAV only when clamd runs: clamscan loads about a gigabyte of signatures for each run, not a background
job; labyrinth-scan-watch already scans Downloads, Desktop and drives with it): a notice when it refuses the file or ClamAV
names it. **While a game runs** (`yggdrasil-gametime status`, asked at most once a minute, only while something waits) the heavy
part waits for the game to end; the light checks keep running, at nice 10 and idle I/O as before.

**Drives.** When a drive is mounted under `/run/media/$USER` (udisks2), a notice "Drive NAME connected" offers **Scan this
drive**. Nothing is scanned unless I press it. The scan (`heimdall-fileguard scan-drive FOLDER`: up to 100,000 files, not
following links) runs in a scope of its own (`systemd-run --user --scope`, 2 GiB, nice 10, idle I/O), outside the guard's own
512 MiB limit, and ends with a notice ("N files checked: R not safe to use, W worth a look") whose Show details lists them.

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
- safe file intake (`src/extract/tests.rs`, `src/scan/tests.rs`, `tests/cli.rs`): archives built byte by byte in the tests: a
  classic ZIP bomb, many small bombs that only the overall ratio catches, overlapping entries (Fifield's) and entries sharing one
  header (a quine), more entries than the limit, a header that says less or more than the file holds, a wrong checksum, two names
  for one file, zip slip names (`..`, absolute, `C:`, backslashes, a `..` that only appears once cleaned), links, devices,
  FIFOs, encrypted entries, archives in archives, every cut-short version of a ZIP, a tar and a tar.gz, a tar.gz bomb, GNU and
  pax long names, a base-256 size, and xz, zstd and bzip2 bombs through the system's programs where installed. Every bomb test
  stops after a few megabytes. ClamAV is a stand-in script (the only "virus" is the EICAR test string, put together at run time);
  the commands' JSON keys and exit codes are checked as Yggdrasil uses them; the sandbox is checked in a child process (the home
  cannot be read, nothing outside OUTDIR written); the watcher refuses a program dressed as a font copied into Documents and a
  ZIP bomb in Downloads, and follows `folders_guard`.

**Fuzzing.** Seven targets (`src/fuzzing.rs`): the guard under every file name, every cleaner (and its output cleaned again),
the ZIP reader, the PDF scanner, the markup reader, the look-alike check, and the extraction's dry run (ZIP, tar, gzip, names;
never more unpacked than its limit). `cargo +nightly fuzz run privacy_guard seeds/privacy_guard` (and `privacy_strip`,
`privacy_zip`, `privacy_pdf`, `privacy_markup`, `privacy_lookalike`, `privacy_extract`) in
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
- The downloads guard lists archives other than ZIP, it does not open them: a document inside a 7z is not checked. `extract` and
  `scan` open tar and compressed tar too, but never 7z or RAR.
- `scan` and `extract` look one level into archives: an archive inside is checked by its own dry run when it is unpacked, not
  before. ClamAV in the background guard needs the clamd daemon (off by default on Labyrinth OS); without it, ClamAV checks
  new files only where labyrinth-scan-watch looks (Downloads, Desktop, drives) or when `scan` is asked.
- The watcher's own folders follow the same 4096-watch cap: a Pictures folder with thousands of sub-folders is watched in part
  (the download folders first).
- Remove hidden info works on what the format holds as metadata. It does not remove what is in the content: a name typed in a
  document, comments and tracked changes (their authors stay: accept or remove them in the office app), a face or a street sign
  in a photo, Word's rsid attributes inside the text (only the settings' list goes), pictures' own metadata inside a PDF or an
  Office file, XMP inside fonts. A PDF over 1 GiB, an encrypted PDF or ZIP, and the refused kinds above are not cleaned.
- Look-alike detection uses a small table, not the whole confusables.txt: it catches what imitates ASCII letters and digits,
  not look-alikes between two non-Latin scripts.
