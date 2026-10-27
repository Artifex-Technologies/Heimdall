package trust

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ChildCommand is the hidden heimdalld command a restore runs as a folder's owner (see writeAsOwner).
const ChildCommand = "__trust-write"

// writeAsOwner puts a file back in a folder that belongs to someone other than root by writing it AS that owner: heimdalld is
// started again as a child with the owner's user and group (the kernel drops root before it runs), so a link planted in the
// user's folder can only lead where that user could write anyway. Tests replace it.
var writeAsOwner = func(path string, data []byte, uid, gid uint32) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, ChildCommand, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}}
	cmd.Stdin = bytes.NewReader(data)
	cmd.Env = []string{"PATH=/usr/bin"}
	cmd.Dir = "/"
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restoring %s as uid %d: %v %s", path, uid, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// WriteChild is the child's side of writeAsOwner: it already runs as the folder's owner and writes stdin to path.
func WriteChild(path string) error {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<20))
	if err != nil {
		return err
	}
	return writeOwned(path, data)
}

func writeOwned(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFile(path, data, 0o644)
}

// ownerOf is the owner of the closest folder above path that exists. Every existing part of the way is looked at without
// following links, and a link anywhere on it is refused: a restore never goes where a link points.
func ownerOf(path string) (uid, gid uint32, err error) {
	dir := filepath.Dir(filepath.Clean(path))
	for {
		fi, err := os.Lstat(dir)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return 0, 0, fmt.Errorf("%s is a link: not restoring through it", dir)
			}
			if !fi.IsDir() {
				return 0, 0, fmt.Errorf("%s is not a folder", dir)
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, 0, fmt.Errorf("no owner for %s", dir)
			}
			if err := noLinksAbove(dir); err != nil {
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

// noLinksAbove refuses a path whose folders include a link.
func noLinksAbove(dir string) error {
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a link: not restoring through it", d)
		}
		if d == "/" || d == "." {
			return nil
		}
	}
}

// rootOnly reports why root may not write into dir: every folder from / down to it must be root's and writable by nobody
// else, or a user could swap something in on the way.
func rootOnly(dir string) error {
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

// restoreFile puts data at path: as the owner of its folder, or as root only inside root-only folders.
func restoreFile(path string, data []byte) error {
	uid, gid, err := ownerOf(path)
	if err != nil {
		return err
	}
	if uid != 0 {
		return writeAsOwner(path, data, uid, gid)
	}
	if err := rootOnly(filepath.Dir(path)); err != nil {
		return err
	}
	return writeOwned(path, data)
}
