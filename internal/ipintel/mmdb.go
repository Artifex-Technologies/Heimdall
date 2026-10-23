// Package ipintel says where a remote address belongs: its country and the network (autonomous system) that announces it,
// from an IP database file on this computer. Nothing is looked up online: no address Heimdall sees ever leaves the machine.
//
// The file is in the MaxMind DB format, which IPinfo's free "Lite" database (country + ASN) and DB-IP's free databases use.
// This is a small reader written from the format's published specification (no third-party code): a binary search tree
// over the address bits, then a data section of typed values. It only reads; it never writes the file.
package ipintel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
)

var metaMarker = []byte("\xab\xcd\xefMaxMind.com")

// DB is one opened database file, held in memory (the free country+ASN files are tens of megabytes).
type DB struct {
	buf        []byte
	nodeCount  uint
	recordSize uint
	ipVersion  uint
	dataStart  uint
	treeSize   uint
	v4Start    uint
	Type       string // database_type from its metadata, e.g. "ipinfo_lite.mmdb"
	BuildEpoch uint64
}

// Open reads and checks a database file.
func Open(path string) (*DB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromBytes(b)
}

// FromBytes uses an in-memory database.
func FromBytes(b []byte) (*DB, error) {
	i := bytes.LastIndex(b, metaMarker)
	if i < 0 {
		return nil, errors.New("not an IP database (no metadata marker)")
	}
	d := &decoder{buf: b[i+len(metaMarker):]}
	v, _, err := d.decode(0, 0)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	meta, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("metadata is not a map")
	}
	db := &DB{buf: b}
	db.nodeCount = uint(toU64(meta["node_count"]))
	db.recordSize = uint(toU64(meta["record_size"]))
	db.ipVersion = uint(toU64(meta["ip_version"]))
	db.BuildEpoch = toU64(meta["build_epoch"])
	db.Type, _ = meta["database_type"].(string)
	if db.recordSize != 24 && db.recordSize != 28 && db.recordSize != 32 {
		return nil, fmt.Errorf("unsupported record size %d", db.recordSize)
	}
	if db.ipVersion != 4 && db.ipVersion != 6 {
		return nil, fmt.Errorf("unsupported ip version %d", db.ipVersion)
	}
	db.treeSize = db.nodeCount * db.recordSize / 4 // two records per node, recordSize bits each
	db.dataStart = db.treeSize + 16
	if db.nodeCount == 0 || db.dataStart > uint(i) {
		return nil, errors.New("search tree is larger than the file")
	}
	// IPv4 addresses sit under 96 zero bits in an IPv6 tree.
	if db.ipVersion == 6 {
		node := uint(0)
		for k := 0; k < 96 && node < db.nodeCount; k++ {
			node, err = db.record(node, 0)
			if err != nil {
				return nil, err
			}
		}
		db.v4Start = node
	}
	return db, nil
}

func (db *DB) record(node, bit uint) (uint, error) {
	off := node * db.recordSize / 4
	if off+db.recordSize/4 > db.treeSize {
		return 0, errors.New("search tree is broken")
	}
	b := db.buf[off:]
	switch db.recordSize {
	case 24:
		b = b[bit*3:]
		return uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2]), nil
	case 28:
		if bit == 0 {
			return uint(b[3]&0xF0)<<20 | uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2]), nil
		}
		return uint(b[3]&0x0F)<<24 | uint(b[4])<<16 | uint(b[5])<<8 | uint(b[6]), nil
	default:
		return uint(binary.BigEndian.Uint32(b[bit*4:])), nil
	}
}

// Lookup returns the record for an address (nil when the database has none for it).
func (db *DB) Lookup(ip net.IP) (map[string]any, error) {
	bits := ip.To16()
	node := uint(0)
	nbits := 128
	if v4 := ip.To4(); v4 != nil {
		bits, nbits = v4, 32
		if db.ipVersion == 6 {
			node = db.v4Start
		}
	} else if db.ipVersion == 4 {
		return nil, nil // an IPv4-only database knows nothing about IPv6
	}
	if bits == nil {
		return nil, errors.New("not an IP address")
	}
	for k := 0; k < nbits && node < db.nodeCount; k++ {
		bit := uint(bits[k/8]>>(7-uint(k%8))) & 1
		var err error
		if node, err = db.record(node, bit); err != nil {
			return nil, err
		}
	}
	if node == db.nodeCount {
		return nil, nil // known to have no data
	}
	if node < db.nodeCount {
		return nil, nil // ran out of address bits inside the tree
	}
	off := node - db.nodeCount - 16
	if db.dataStart+off >= uint(len(db.buf)) {
		return nil, errors.New("data pointer outside the file")
	}
	d := &decoder{buf: db.buf[db.dataStart:]}
	v, _, err := d.decode(off, 0)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

// decoder reads the data section's typed values.
type decoder struct{ buf []byte }

const maxDepth = 32 // nesting and pointer chains are bounded, so a broken file cannot recurse forever

func (d *decoder) byte(off uint) (byte, error) {
	if off >= uint(len(d.buf)) {
		return 0, errors.New("value runs past the end")
	}
	return d.buf[off], nil
}

func (d *decoder) bytes(off, n uint) ([]byte, error) {
	if off+n > uint(len(d.buf)) || off+n < off {
		return nil, errors.New("value runs past the end")
	}
	return d.buf[off : off+n], nil
}

// decode reads the value at off and returns it with the offset just after it.
func (d *decoder) decode(off uint, depth int) (any, uint, error) {
	if depth > maxDepth {
		return nil, 0, errors.New("values nested too deeply")
	}
	ctrl, err := d.byte(off)
	if err != nil {
		return nil, 0, err
	}
	off++
	typ := uint(ctrl >> 5)
	if typ == 1 { // pointer: the value lives elsewhere; reading continues after the pointer itself
		ss, vvv := uint(ctrl>>3)&3, uint(ctrl&7)
		b, err := d.bytes(off, ss+1)
		if err != nil {
			return nil, 0, err
		}
		var p uint
		switch ss {
		case 0:
			p = vvv<<8 | uint(b[0])
		case 1:
			p = (vvv<<16 | uint(b[0])<<8 | uint(b[1])) + 2048
		case 2:
			p = (vvv<<24 | uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2])) + 526336
		default:
			p = uint(binary.BigEndian.Uint32(b))
		}
		v, _, err := d.decode(p, depth+1)
		return v, off + ss + 1, err
	}
	if typ == 0 { // extended type in the next byte
		b, err := d.byte(off)
		if err != nil {
			return nil, 0, err
		}
		typ = 7 + uint(b)
		off++
	}
	size := uint(ctrl & 0x1f)
	switch size {
	case 29, 30, 31:
		n := size - 28
		b, err := d.bytes(off, n)
		if err != nil {
			return nil, 0, err
		}
		off += n
		switch size {
		case 29:
			size = 29 + uint(b[0])
		case 30:
			size = 285 + (uint(b[0])<<8 | uint(b[1]))
		default:
			size = 65821 + (uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2]))
		}
	}
	switch typ {
	case 2: // UTF-8 string
		b, err := d.bytes(off, size)
		return string(b), off + size, err
	case 3: // double
		b, err := d.bytes(off, 8)
		if err != nil || size != 8 {
			return nil, 0, errors.New("bad double")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), off + 8, nil
	case 4: // bytes
		b, err := d.bytes(off, size)
		return append([]byte(nil), b...), off + size, err
	case 5, 6, 9, 10: // unsigned integers (uint128 is kept to its low 64 bits; nothing here needs more)
		if size > 16 {
			return nil, 0, errors.New("integer too long")
		}
		b, err := d.bytes(off, size)
		if err != nil {
			return nil, 0, err
		}
		var v uint64
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
		return v, off + size, nil
	case 8: // int32
		if size > 4 {
			return nil, 0, errors.New("int32 too long")
		}
		b, err := d.bytes(off, size)
		if err != nil {
			return nil, 0, err
		}
		var v uint32
		for _, x := range b {
			v = v<<8 | uint32(x)
		}
		return int64(int32(v)), off + size, nil
	case 7: // map
		m := make(map[string]any, min(size, 64))
		for i := uint(0); i < size; i++ {
			k, next, err := d.decode(off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, 0, errors.New("map key is not a string")
			}
			v, next2, err := d.decode(next, depth+1)
			if err != nil {
				return nil, 0, err
			}
			m[key] = v
			off = next2
		}
		return m, off, nil
	case 11: // array
		a := make([]any, 0, min(size, 64))
		for i := uint(0); i < size; i++ {
			v, next, err := d.decode(off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			a = append(a, v)
			off = next
		}
		return a, off, nil
	case 14: // boolean: the value is the size
		return size != 0, off, nil
	case 15: // float
		b, err := d.bytes(off, 4)
		if err != nil || size != 4 {
			return nil, 0, errors.New("bad float")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), off + 4, nil
	}
	return nil, 0, fmt.Errorf("unknown value type %d", typ)
}

func toU64(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case int64:
		if x > 0 {
			return uint64(x)
		}
	}
	return 0
}
