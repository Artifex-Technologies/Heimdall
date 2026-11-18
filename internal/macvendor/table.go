package macvendor

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// The caps on hostile input (a damaged download, a planted file), as in the Rust crate (src/table.rs).
const (
	MaxLine    = 4096     // the longest line kept, in bytes
	MaxRecord  = 16384    // the longest CSV record (lines joined by a quoted line break); a longer one is dropped
	MaxEntries = 1 << 20  // the most blocks a table holds
	MaxFile    = 64 << 20 // the largest file read
)

type entry struct {
	key      uint64
	name     uint32
	registry Registry
}

type name struct {
	full, short       uint32
	fullLen, shortLen uint16
}

type bitsEntries struct {
	bits    uint8
	entries []entry
}

// Table holds the blocks of every registry loaded, one sorted slice per block size (longest first), every name stored once.
type Table struct {
	byBits []bitsEntries
	names  []name
	text   string
}

// Load reads the files in paths: for each registry the first of its files that gives at least one block. MA-S: oui36.csv,
// oui36.txt; IAB: iab.csv, iab.txt, then hwdata's iab.txt; MA-M: mam.csv, mam.txt; MA-L: oui.csv, oui.txt, then hwdata's
// oui.txt. No file at all gives an empty table (every maker unknown).
func Load(paths DataPaths) *Table {
	b := NewBuilder()
	slots := []struct {
		registry Registry
		ieee     []string
		hwdata   string
	}{
		{MaS, []string{"oui36.csv", "oui36.txt"}, ""},
		{IAB, []string{"iab.csv", "iab.txt"}, "iab.txt"},
		{MaM, []string{"mam.csv", "mam.txt"}, ""},
		{MaL, []string{"oui.csv", "oui.txt"}, "oui.txt"},
	}
	for _, s := range slots {
		var files []string
		for _, f := range s.ieee {
			files = append(files, filepath.Join(paths.IEEEDir, f))
		}
		if s.hwdata != "" {
			files = append(files, filepath.Join(paths.HwdataDir, s.hwdata))
		}
		for _, f := range files {
			if b.ReadFile(f, s.registry) > 0 {
				break
			}
		}
	}
	return b.Finish()
}

// Lookup says what the address is: a special address, multicast, private (locally administered), a registered maker's (the
// longest block wins) or unknown.
func (t *Table) Lookup(mac [6]byte) Answer {
	if s := findSpecial(mac); s != nil {
		return Answer{Kind: KindSpecial, Name: s.Name, Short: s.Short}
	}
	if IsMulticast(mac) {
		return Answer{Kind: KindMulticast}
	}
	if IsLocal(mac) {
		return Answer{Kind: KindPrivate}
	}
	v := macValue(mac)
	for _, be := range t.byBits {
		if e := find(be.entries, v>>(48-uint(be.bits))); e != nil {
			return t.vendor(e, be.bits)
		}
	}
	return Answer{Kind: KindUnknown}
}

// LookupString is Lookup on an address as text (ParseMAC); Kind invalid when it is not one.
func (t *Table) LookupString(mac string) Answer {
	m, ok := ParseMAC(mac)
	if !ok {
		return Answer{Kind: KindInvalid}
	}
	return t.Lookup(m)
}

// LookupOUI is the company a 24-bit identifier is registered to (MA-L).
func (t *Table) LookupOUI(oui [3]byte) (Answer, bool) {
	key := uint64(oui[0])<<16 | uint64(oui[1])<<8 | uint64(oui[2])
	for _, be := range t.byBits {
		if be.bits == 24 {
			if e := find(be.entries, key); e != nil {
				return t.vendor(e, 24), true
			}
		}
	}
	return Answer{}, false
}

// Len is how many blocks the table holds.
func (t *Table) Len() int {
	n := 0
	for _, be := range t.byBits {
		n += len(be.entries)
	}
	return n
}

func (t *Table) vendor(e *entry, bits uint8) Answer {
	n := t.names[e.name]
	return Answer{Kind: KindVendor, Name: t.text[n.full : n.full+uint32(n.fullLen)], Short: t.text[n.short : n.short+uint32(n.shortLen)],
		Registry: e.registry, Bits: bits}
}

func find(entries []entry, key uint64) *entry {
	i := sort.Search(len(entries), func(i int) bool { return entries[i].key >= key })
	if i < len(entries) && entries[i].key == key {
		return &entries[i]
	}
	return nil
}

type rawEntry struct {
	bits     uint8
	key      uint64
	registry Registry
	name     uint32
}

// Builder collects blocks from files, then sorts them into a Table.
type Builder struct {
	raw    []rawEntry
	names  []name
	text   strings.Builder
	intern map[string]uint32
}

// NewBuilder is an empty builder.
func NewBuilder() *Builder { return &Builder{intern: map[string]uint32{}} }

// ReadFile reads one file (Read); a missing file, one that is not a regular file or one over MaxFile adds nothing. It returns
// how many blocks it added.
func (b *Builder) ReadFile(path string, hint Registry) int {
	// non-blocking, so a FIFO put in the folder cannot stall the open; it is refused just below
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxFile {
		return 0
	}
	return b.Read(io.LimitReader(f, MaxFile), hint)
}

// Read reads a text list or a CSV file (the first line tells which); hint is the registry of a text list's blocks (the CSV
// files name their own). It returns how many blocks it added.
func (b *Builder) Read(r io.Reader, hint Registry) int {
	before := len(b.raw)
	br := bufio.NewReader(r)
	line, ok := nextLine(br, nil)
	if !ok {
		return 0
	}
	line = bytes.TrimPrefix(line, []byte("\xef\xbb\xbf"))
	if len(line) >= 9 && asciiEqualFold(line[:9], []byte("registry,")) {
		b.readCSV(line, br)
	} else {
		b.readTxt(line, br, hint)
	}
	return len(b.raw) - before
}

func (b *Builder) readTxt(line []byte, r *bufio.Reader, hint Registry) {
	last := -1 // the block on the last "(hex)" line, until its "(base 16)" line says whether it is smaller than 24 bits
	for {
		if at := bytes.Index(line, []byte("(hex)")); at >= 0 {
			last = -1
			if p, ok := prefix24(trim(line[:at])); ok {
				last = b.Add(24, p, hint, line[at+5:])
			}
		} else if at := bytes.Index(line, []byte("(base 16)")); at >= 0 && last >= 0 {
			i := last
			last = -1
			if bits, key, ok := rangeIn(b.raw[i].key, trim(line[:at])); ok {
				b.raw[i].bits, b.raw[i].key = bits, key
			}
		}
		var ok bool
		if line, ok = nextLine(r, line); !ok {
			return
		}
	}
}

func (b *Builder) readCSV(line []byte, r *bufio.Reader) {
	rec := &csvRecord{}
	for {
		if rec.line(line) {
			if rec.fields >= 3 {
				b.csvRow(rec.cols)
			}
			rec = &csvRecord{}
		} else if rec.bytes > MaxRecord {
			rec = &csvRecord{}
		}
		var ok bool
		if line, ok = nextLine(r, line); !ok {
			return
		}
	}
}

func (b *Builder) csvRow(cols [3][]byte) {
	registry, ok := RegistryFromName(string(cols[0]))
	if !ok {
		return
	}
	a := trim(cols[1])
	if len(a) < 6 || len(a) > 11 {
		return
	}
	var key uint64
	for _, c := range a {
		v, ok := hexValue(c)
		if !ok {
			return
		}
		key = key<<4 | uint64(v)
	}
	b.Add(uint8(4*len(a)), key, registry, cols[2])
}

// Add adds one block of bits leading bits; rawName is cleaned (Clean); an empty name or a full table adds nothing (-1). It
// returns the block's place in the order read.
func (b *Builder) Add(bits uint8, key uint64, registry Registry, rawName []byte) int {
	if len(b.raw) >= MaxEntries || bits < 1 || bits > 48 || key>>bits != 0 {
		return -1
	}
	full := Clean(rawName)
	if full == "" {
		return -1
	}
	id, ok := b.intern[full]
	if !ok {
		short := Short(full)
		at := uint32(b.text.Len())
		b.text.WriteString(full)
		shortAt := at
		// the short name is usually the start of the full one: stored once
		if !strings.HasPrefix(full, short) {
			shortAt = uint32(b.text.Len())
			b.text.WriteString(short)
		}
		id = uint32(len(b.names))
		b.names = append(b.names, name{full: at, fullLen: uint16(len(full)), short: shortAt, shortLen: uint16(len(short))})
		b.intern[full] = id
	}
	b.raw = append(b.raw, rawEntry{bits, key, registry, id})
	return len(b.raw) - 1
}

// Finish sorts the blocks by size (longest first) and prefix; of two blocks with the same prefix the first read stays.
func (b *Builder) Finish() *Table {
	var byBits []bitsEntries
	for _, r := range b.raw {
		e := entry{r.key, r.name, r.registry}
		found := false
		for i := range byBits {
			if byBits[i].bits == r.bits {
				byBits[i].entries = append(byBits[i].entries, e)
				found = true
				break
			}
		}
		if !found {
			byBits = append(byBits, bitsEntries{r.bits, []entry{e}})
		}
	}
	sort.Slice(byBits, func(i, j int) bool { return byBits[i].bits > byBits[j].bits })
	for i := range byBits {
		es := byBits[i].entries
		sort.SliceStable(es, func(x, y int) bool { return es[x].key < es[y].key })
		out := es[:0]
		for k, e := range es {
			if k == 0 || e.key != es[k-1].key {
				out = append(out, e)
			}
		}
		byBits[i].entries = append([]entry(nil), out...)
	}
	return &Table{byBits: byBits, names: b.names, text: b.text.String()}
}

// csvRecord is one CSV record being read: the first three fields (registry, assignment, name) kept, the rest counted.
type csvRecord struct {
	cols    [3][]byte
	fields  int
	quoted  bool
	started bool
	bytes   int
}

// line reads one line into the record; true when the record ends with it (no quote left open).
func (r *csvRecord) line(line []byte) bool {
	r.bytes += len(line) + 1
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case r.quoted:
			if c == '"' {
				if i+1 < len(line) && line[i+1] == '"' {
					r.push('"')
					i++
				} else {
					r.quoted = false
				}
			} else {
				r.push(c)
			}
		case c == '"' && !r.started:
			r.quoted = true
			r.started = true
		case c == ',':
			r.fields++
			r.started = false
		default:
			r.push(c)
			r.started = true
		}
	}
	if r.quoted {
		r.push('\n')
		return false
	}
	r.fields++
	return true
}

func (r *csvRecord) push(c byte) {
	if r.fields < len(r.cols) {
		r.cols[r.fields] = append(r.cols[r.fields], c)
	}
}

// nextLine reads the next line without its line break (a '\r' before it goes too), at most MaxLine bytes of it, into buf's
// storage. False at the end of the input (or on a read error) with nothing read.
func nextLine(r *bufio.Reader, buf []byte) ([]byte, bool) {
	buf = buf[:0]
	total := 0
	var last byte
	for {
		chunk, err := r.ReadSlice('\n')
		total += len(chunk)
		content := chunk
		ended := len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
		if ended {
			content = chunk[:len(chunk)-1]
		}
		if len(content) > 0 {
			last = content[len(content)-1]
			if room := MaxLine + 1 - len(buf); room > 0 {
				buf = append(buf, content[:min(len(content), room)]...)
			}
		}
		if ended || (err != nil && err != bufio.ErrBufferFull) {
			break
		}
	}
	if total == 0 {
		return buf, false
	}
	if last == '\r' && len(buf) <= MaxLine {
		buf = buf[:len(buf)-1]
	}
	if len(buf) > MaxLine {
		buf = buf[:MaxLine]
	}
	return buf, true
}

func trim(b []byte) []byte { return bytes.Trim(b, " \t") }

// prefix24 reads "28-6F-B9" as a number.
func prefix24(b []byte) (uint64, bool) {
	if len(b) != 8 || b[2] != '-' || b[5] != '-' {
		return 0, false
	}
	var v uint64
	for i, c := range b {
		if i == 2 || i == 5 {
			continue
		}
		x, ok := hexValue(c)
		if !ok {
			return 0, false
		}
		v = v<<4 | uint64(x)
	}
	return v, true
}

// rangeIn reads a "(base 16)" line's range ("0D7000-0D7FFF") inside the 24-bit block p24: the smaller block's size in bits and
// its prefix. Not ok for a single "286FB9" or a range that is not an aligned power of two.
func rangeIn(p24 uint64, b []byte) (uint8, uint64, bool) {
	if len(b) != 13 || b[6] != '-' {
		return 0, 0, false
	}
	num := func(s []byte) (uint64, bool) {
		var v uint64
		for _, c := range s {
			x, ok := hexValue(c)
			if !ok {
				return 0, false
			}
			v = v<<4 | uint64(x)
		}
		return v, true
	}
	lo, ok1 := num(b[:6])
	hi, ok2 := num(b[7:])
	if !ok1 || !ok2 || hi < lo {
		return 0, 0, false
	}
	size := hi - lo + 1
	if size&(size-1) != 0 || size >= 1<<24 || lo%size != 0 {
		return 0, 0, false
	}
	k := uint(0)
	for size>>k != 1 {
		k++
	}
	return uint8(48 - k), (p24<<24 | lo) >> k, true
}
