package pkgaudit

import "strings"

// Vercmp compares two package versions the way pacman does (alpm_pkg_vercmp: [epoch:]version[-release]): -1, 0 or 1.
func Vercmp(a, b string) int {
	if a == b {
		return 0
	}
	e1, v1, r1 := evr(a)
	e2, v2, r2 := evr(b)
	if c := rpmvercmp(e1, e2); c != 0 {
		return c
	}
	if c := rpmvercmp(v1, v2); c != 0 {
		return c
	}
	if r1 != "" && r2 != "" {
		return rpmvercmp(r1, r2)
	}
	return 0
}

func evr(s string) (epoch, ver, rel string) {
	epoch = "0"
	if i := strings.IndexByte(s, ':'); i >= 0 {
		digits := true
		for _, c := range s[:i] {
			if c < '0' || c > '9' {
				digits = false
			}
		}
		if digits {
			if i > 0 {
				epoch = s[:i]
			}
			s = s[i+1:]
		}
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// rpmvercmp is the segment comparison pacman inherited from rpm.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0 // read positions
	p1, p2 := 0, 0   // end of the previous segment
	for one < len(a) && two < len(b) {
		for one < len(a) && !isAlnum(a[one]) {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) {
			two++
		}
		if one >= len(a) || two >= len(b) {
			break
		}
		if one-p1 != two-p2 { // separators of different length
			if one-p1 < two-p2 {
				return -1
			}
			return 1
		}
		p1, p2 = one, two
		isNum := isDigit(a[p1])
		for p1 < len(a) && (isNum && isDigit(a[p1]) || !isNum && isAlpha(a[p1])) {
			p1++
		}
		for p2 < len(b) && (isNum && isDigit(b[p2]) || !isNum && isAlpha(b[p2])) {
			p2++
		}
		s1, s2 := a[one:p1], b[two:p2]
		if s2 == "" { // the segments are of different kinds
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			s1, s2 = strings.TrimLeft(s1, "0"), strings.TrimLeft(s2, "0")
			if len(s1) != len(s2) {
				if len(s1) > len(s2) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(s1, s2); c != 0 {
			return c
		}
		one, two = p1, p2
	}
	if one >= len(a) && two >= len(b) {
		return 0
	}
	if (one >= len(a) && !(two < len(b) && isAlpha(b[two]))) || (one < len(a) && isAlpha(a[one])) {
		return -1
	}
	return 1
}
