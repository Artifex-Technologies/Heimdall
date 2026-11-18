// Package macvendor says who made a hardware (MAC) address, read offline from the IEEE's registries, and what an address is
// when no maker owns it. It is the Go twin of the Rust crate heimdall-macvendor (rust/macvendor): the same files give the same
// answers (testdata/parity/macvendor.json, written by this package's tests).
//
// The IEEE hands out blocks of three sizes: MA-L (24 bits, the classic OUI), MA-M (28 bits) and MA-S (36 bits; the older IAB
// blocks are 36 bits too). A small company's block sits inside a 24-bit block registered to "IEEE Registration Authority", so
// the longest prefix wins. Before any registry is asked, an address is checked for what it says about itself: well-known
// special addresses (broadcast, multicast ranges, virtual routers, documentation), other group addresses (multicast), and
// locally administered ones (private: made up by phones and computers for Wi-Fi privacy, never a maker's).
//
// The data is IEEE's only: Arch's hwdata (/usr/share/hwdata/oui.txt, iab.txt) by default, and the IEEE's own CSV files
// (oui.csv, mam.csv, oui36.csv, iab.csv) when they are in IEEEDir. The table is loaded once, on first use (Default).
package macvendor

import (
	"strings"
	"sync"
)

// IEEEDir is where the IEEE's own files go when they are downloaded (not done yet: docs/DEVICES.md, "Vendor data"). A folder
// of its own, readable by everyone, because /var/lib/heimdall is closed to other accounts and Settings reads these files too.
const IEEEDir = "/var/lib/heimdall-ieee"

// HwdataDir is Arch's hwdata package: the IEEE's MA-L and IAB lists as text.
const HwdataDir = "/usr/share/hwdata"

// Registry is the IEEE registry a block is in.
type Registry uint8

// The registries, in the Rust crate's order.
const (
	MaL Registry = iota // 24 bits
	MaM                 // 28 bits
	MaS                 // 36 bits
	IAB                 // 36 bits, no longer handed out
)

var registryNames = [...]string{"MA-L", "MA-M", "MA-S", "IAB"}

// String is the IEEE's own name for the registry.
func (r Registry) String() string {
	if int(r) < len(registryNames) {
		return registryNames[r]
	}
	return ""
}

// RegistryFromName reads a registry's name (the CSV files' first column) in any case, spaces and tabs around it ignored.
func RegistryFromName(s string) (Registry, bool) {
	s = strings.Trim(s, " \t")
	for i, n := range registryNames {
		if asciiEqualFold([]byte(s), []byte(n)) {
			return Registry(i), true
		}
	}
	return 0, false
}

// The kinds of answer.
const (
	KindVendor    = "vendor"
	KindSpecial   = "special"
	KindMulticast = "multicast"
	KindPrivate   = "private"
	KindUnknown   = "unknown"
	KindInvalid   = "invalid"
)

// Answer is what an address is. Name and Short are the maker's (Kind vendor) or the special address's (Kind special); Registry
// and Bits are set for a maker only.
type Answer struct {
	Kind     string
	Name     string
	Short    string
	Registry Registry
	Bits     uint8
}

// Label is the name to show beside the address: the maker's or the special address's short name, empty otherwise.
func (a Answer) Label() string { return a.Short }

// IsMulticast reports a group (multicast or broadcast) address: the first byte's lowest bit.
func IsMulticast(mac [6]byte) bool { return mac[0]&0x01 != 0 }

// IsLocal reports a locally administered address (made up, not a maker's): the first byte's second bit.
func IsLocal(mac [6]byte) bool { return mac[0]&0x02 != 0 }

// ParseMAC reads a hardware address: six pairs of hex digits split by ':' or '-' (one kind throughout), Cisco's three groups
// of four split by '.', or twelve hex digits; spaces and tabs around it are ignored.
func ParseMAC(s string) ([6]byte, bool) {
	var mac [6]byte
	b := []byte(strings.Trim(s, " \t"))
	var digits [12]byte
	n := 0
	push := func(c byte) bool {
		v, ok := hexValue(c)
		if !ok || n >= 12 {
			return false
		}
		digits[n] = v
		n++
		return true
	}
	ok := true
	switch len(b) {
	case 17:
		for i, c := range b {
			if i%3 == 2 {
				if (c != ':' && c != '-') || c != b[2] {
					ok = false
				}
			} else if !push(c) {
				ok = false
			}
			if !ok {
				break
			}
		}
	case 14:
		for i, c := range b {
			if i%5 == 4 {
				ok = c == '.'
			} else {
				ok = push(c)
			}
			if !ok {
				break
			}
		}
	case 12:
		for _, c := range b {
			if ok = push(c); !ok {
				break
			}
		}
	default:
		ok = false
	}
	if !ok || n != 12 {
		return mac, false
	}
	for i := range mac {
		mac[i] = digits[2*i]<<4 | digits[2*i+1]
	}
	return mac, true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func macValue(mac [6]byte) uint64 {
	var v uint64
	for _, b := range mac {
		v = v<<8 | uint64(b)
	}
	return v
}

// DataPaths says where the table's files are.
type DataPaths struct {
	IEEEDir   string // the IEEE's own files (oui.csv, mam.csv, oui36.csv, iab.csv; the .txt forms too)
	HwdataDir string // Arch's hwdata (oui.txt, iab.txt), for a registry the IEEE folder has no usable file for
}

// DefaultPaths is IEEEDir and HwdataDir.
func DefaultPaths() DataPaths { return DataPaths{IEEEDir: IEEEDir, HwdataDir: HwdataDir} }

var global = sync.OnceValue(func() *Table { return Load(DefaultPaths()) })

// Default is the table from this computer's files, loaded on the first call and kept.
func Default() *Table { return global() }
