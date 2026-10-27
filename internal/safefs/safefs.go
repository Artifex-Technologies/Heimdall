// Package safefs is how Heimdall, running as root, touches files in places other users can write: never through a link, and
// a user's files only as that user. Trust's restore and immunity's hold and release go through it.
package safefs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ChildCommand is the hidden heimdalld command that does a write already running as the file's owner (see WriteAs).
const ChildCommand = "__write-as-owner"

// openHow is the kernel's struct open_how for openat2(2).
type openHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

const (
	sysOpenat2         = 437 // x86_64 and arm64 share the number
	resolveNoSymlinks  = 0x04
	resolveNoMagicLink = 0x02
)

// OpenNoLinks opens path refusing a link anywhere on it (openat2 RESOLVE_NO_SYMLINKS). On a kernel without openat2 it falls
// back to O_NOFOLLOW on the last part and a check of every folder on the way.
func OpenNoLinks(path string, flags int, mode os.FileMode) (*os.File, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	how := openHow{Flags: uint64(flags | syscall.O_CLOEXEC), Mode: uint64(mode.Perm()), Resolve: resolveNoSymlinks | resolveNoMagicLink}
	fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(^uint(99)), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0) // AT_FDCWD = -100
	if errno == 0 {
		return os.NewFile(fd, path), nil
	}
	if errno != syscall.ENOSYS {
		return nil, &os.PathError{Op: "open", Path: path, Err: errno}
	}
	if err := NoLinksAbove(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
}

// NoLinksAbove refuses a folder path that includes a link.
func NoLinksAbove(dir string) error {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a link: not going through it", d)
		}
		if d == "/" || d == "." {
			return nil
		}
	}
}

// OwnerOf is the owner of the closest folder above path that exists, looked at without following links; a link anywhere on
// the way is refused.
func OwnerOf(path string) (uid, gid uint32, err error) {
	dir := filepath.Dir(filepath.Clean(path))
	for {
		fi, err := os.Lstat(dir)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return 0, 0, fmt.Errorf("%s is a link: not going through it", dir)
			}
			if !fi.IsDir() {
				return 0, 0, fmt.Errorf("%s is not a folder", dir)
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, 0, fmt.Errorf("no owner for %s", dir)
			}
			if err := NoLinksAbove(dir); err != nil {
				return 0, 0, err
			}
			return st.Uid, st.Gid, nil
		}
		if !os.IsNotExist(err) {
			return 0, 0, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return 0, 0, fmt.Errorf("no existing folder above %s", path)
		}
		dir = parent
	}
}

// RootOnly says why root may not write into dir: every existing folder from / down to it must be root's, not a link, and
// writable by nobody else, or a user could swap something in on the way.
func RootOnly(dir string) error {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err == nil {
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("%s is not a root-only folder: not writing there as root", d)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if d == "/" {
			return nil
		}
	}
}

// File is what to write: the bytes, the mode, an optional modification time, and whether an existing file may be replaced.
type File struct {
	Data      []byte
	Mode      os.FileMode
	MTime     time.Time // zero: now
	Exclusive bool      // never replace a file (or link) already there
}

// WriteAs writes path as uid/gid: heimdalld started again with that user and group (the kernel drops root before it runs).
// Tests replace it.
var WriteAs = func(path string, f File, uid, gid uint32) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.HasSuffix(exe, ".test") { // a test binary started again would run every test again, forever
		return fmt.Errorf("safefs.WriteAs from a test binary: replace WriteAs in the test")
	}
	mt := int64(0)
	if !f.MTime.IsZero() {
		mt = f.MTime.UnixNano()
	}
	cmd := exec.Command(exe, ChildCommand, path, strconv.FormatUint(uint64(f.Mode.Perm()), 8), strconv.FormatInt(mt, 10), strconv.FormatBool(f.Exclusive))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}}
	cmd.Stdin = bytes.NewReader(f.Data)
	cmd.Env = []string{"PATH=/usr/bin"}
	cmd.Dir = "/"
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("writing %s as uid %d: %v %s", path, uid, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Child is the child's side of WriteAs (args: path, octal mode, mtime in ns or 0, exclusive): it runs as the owner already.
func Child(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: %s PATH MODE MTIME EXCLUSIVE", ChildCommand)
	}
	mode, err1 := strconv.ParseUint(args[1], 8, 32)
	mt, err2 := strconv.ParseInt(args[2], 10, 64)
	excl, err3 := strconv.ParseBool(args[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("bad arguments")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 256<<20))
	if err != nil {
		return err
	}
	f := File{Data: data, Mode: os.FileMode(mode), Exclusive: excl}
	if mt != 0 {
		f.MTime = time.Unix(0, mt)
	}
	return write(args[0], f)
}

// write puts f at path from the current user's rights: folders made as needed, never through a link, through a temporary
// file and a rename (or, exclusive, straight into a new file).
func write(path string, f File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := NoLinksAbove(filepath.Dir(path)); err != nil {
		return err
	}
	target := path
	if !f.Exclusive {
		target = path + ".heimdall-tmp"
		_ = os.Remove(target)
	}
	out, err := OpenNoLinks(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.Mode)
	if err != nil {
		return err
	}
	_, werr := out.Write(f.Data)
	if werr == nil {
		werr = out.Chmod(f.Mode.Perm())
	}
	if werr == nil && !f.MTime.IsZero() {
		werr = os.Chtimes(target, f.MTime, f.MTime) // the new file is ours and in a link-free folder
	}
	cerr := out.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(target)
		return werr
	}
	if !f.Exclusive {
		return os.Rename(target, path)
	}
	return nil
}

// Put writes path as the owner of its folder, or as root only inside root-only folders.
func Put(path string, f File) error {
	uid, gid, err := OwnerOf(path)
	if err != nil {
		return err
	}
	return PutAs(path, f, uid, gid)
}

// PutAs writes path as uid/gid; as root (uid 0) only inside root-only folders.
func PutAs(path string, f File, uid, gid uint32) error {
	if uid != 0 {
		return WriteAs(path, f, uid, gid)
	}
	if err := RootOnly(filepath.Dir(path)); err != nil {
		return err
	}
	return write(path, f)
}

// WriteForTest is write, for other packages' tests that stand in for WriteAs (they do not run as root).
func WriteForTest(path string, f File) error { return write(path, f) }
