package lan

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// A small DNS message codec, enough for multicast DNS discovery and one reverse lookup (Heimdall stays stdlib-only, and the
// standard library's resolver does not do mDNS). Only the record types discovery reads are decoded; the rest are skipped.

const (
	typeA    = 1
	typePTR  = 12
	typeTXT  = 16
	typeAAAA = 28
	typeSRV  = 33
	typeANY  = 255
)

type record struct {
	name  string
	rtype uint16
	ptr   string   // PTR target, SRV target
	ip    net.IP   // A, AAAA
	txt   []string // TXT strings
	port  uint16   // SRV
}

// query builds a message asking for each name's PTR records (a standard query: answers go to the group, which the firewall lets in).
func query(names []string) []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[4:], uint16(len(names)))
	for _, n := range names {
		for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
		b = append(b, 0, 0, typePTR, 0, 1)
	}
	return b
}

var errShort = errors.New("short dns message")

// readName decodes a possibly compressed name at off, returning it and the offset after it.
func readName(m []byte, off int) (string, int, error) {
	var labels []string
	end, jumps := -1, 0
	for {
		if off >= len(m) {
			return "", 0, errShort
		}
		l := int(m[off])
		switch {
		case l == 0:
			off++
			if end < 0 {
				end = off
			}
			return strings.Join(labels, "."), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(m) || jumps > 16 {
				return "", 0, errShort
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(m[off:]) & 0x3fff)
			jumps++
		default:
			if off+1+l > len(m) {
				return "", 0, errShort
			}
			labels = append(labels, string(m[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

// parse returns every answer, authority and additional record of a response (questions are skipped).
func parse(m []byte) ([]record, error) {
	if len(m) < 12 {
		return nil, errShort
	}
	if m[2]&0x80 == 0 {
		return nil, errors.New("not a response")
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	rr := int(binary.BigEndian.Uint16(m[6:])) + int(binary.BigEndian.Uint16(m[8:])) + int(binary.BigEndian.Uint16(m[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, o, err := readName(m, off)
		if err != nil {
			return nil, err
		}
		off = o + 4
	}
	var out []record
	for i := 0; i < rr && i < 256; i++ {
		name, o, err := readName(m, off)
		if err != nil || o+10 > len(m) {
			return out, errShort
		}
		r := record{name: name, rtype: binary.BigEndian.Uint16(m[o:])}
		rdlen := int(binary.BigEndian.Uint16(m[o+8:]))
		data := o + 10
		if data+rdlen > len(m) {
			return out, errShort
		}
		switch r.rtype {
		case typeA:
			if rdlen == 4 {
				r.ip = net.IP(append([]byte(nil), m[data:data+4]...))
			}
		case typeAAAA:
			if rdlen == 16 {
				r.ip = net.IP(append([]byte(nil), m[data:data+16]...))
			}
		case typePTR:
			r.ptr, _, _ = readName(m, data)
		case typeSRV:
			if rdlen >= 7 {
				r.port = binary.BigEndian.Uint16(m[data+4:])
				r.ptr, _, _ = readName(m, data+6)
			}
		case typeTXT:
			for p := data; p < data+rdlen; {
				l := int(m[p])
				if p+1+l > data+rdlen {
					break
				}
				r.txt = append(r.txt, string(m[p+1:p+1+l]))
				p += 1 + l
			}
		}
		out = append(out, r)
		off = data + rdlen
	}
	return out, nil
}
