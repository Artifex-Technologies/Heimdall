package immunity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// The inventory is what Heimdall saw on the computer and since when: each program outside the packages (the places below) with
// the SHA-256 of its content. It is how "this file was here before" is proven without anyone's word: a held file whose exact content
// the inventory had at that path a day or more before it was held may be released on that proof alone.
//
// Root keeps it (heimdall-inventory.timer, daily): neither the user nor Sarina nor the daemon's account can write it.

// InventoryRoots are the places looked at: programs installed by hand, per-user programs and user services.
var InventoryRoots = []string{"/usr/local/bin", "/usr/local/sbin", "/usr/local/lib", "/opt", "/home/*/.local/bin", "/home/*/bin", "/home/*/.config/systemd/user", "/home/*/.local/share/applications"}

const (
	maxInventoryFiles = 50000
	maxInventoryBytes = 128 << 20
)

// Seen is one file in the inventory.
type Seen struct {
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	MTime     int64     `json:"mtime"`
	FirstSeen time.Time `json:"first_seen"` // with this content
	LastSeen  time.Time `json:"last_seen"`
}

func (s Store) inventoryPath() string { return filepath.Join(s.Dir, "inventory.json") }

// Inventory reads the inventory.
func (s Store) Inventory() map[string]Seen {
	inv := map[string]Seen{}
	if b, err := os.ReadFile(s.inventoryPath()); err == nil {
		_ = json.Unmarshal(b, &inv)
	}
	return inv
}

// TakeInventory looks at the roots again: unchanged files (same size and time) keep their hash and first sighting, changed ones
// start again, files gone are dropped. Only executables, unit files and desktop entries count.
func (s Store) TakeInventory(roots []string) (int, error) {
	old := s.Inventory()
	now := time.Now().UTC().Truncate(time.Second)
	inv := map[string]Seen{}
	for _, pattern := range roots {
		matches, _ := filepath.Glob(pattern)
		for _, root := range matches {
			_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || len(inv) >= maxInventoryFiles {
					return nil
				}
				if !d.Type().IsRegular() {
					return nil
				}
				info, err := d.Info()
				if err != nil || info.Size() > maxInventoryBytes {
					return nil
				}
				ext := filepath.Ext(p)
				if info.Mode().Perm()&0o111 == 0 && ext != ".service" && ext != ".timer" && ext != ".desktop" {
					return nil
				}
				if o, ok := old[p]; ok && o.Size == info.Size() && o.MTime == info.ModTime().UnixNano() {
					o.LastSeen = now
					inv[p] = o
					return nil
				}
				f, err := os.Open(p)
				if err != nil {
					return nil
				}
				h := sha256.New()
				_, err = io.Copy(h, f)
				f.Close()
				if err != nil {
					return nil
				}
				sum := hex.EncodeToString(h.Sum(nil))
				first := now
				if o, ok := old[p]; ok && o.SHA256 == sum {
					first = o.FirstSeen
				}
				inv[p] = Seen{SHA256: sum, Size: info.Size(), MTime: info.ModTime().UnixNano(), FirstSeen: first, LastSeen: now}
				return nil
			})
		}
	}
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return 0, err
	}
	b, _ := json.Marshal(inv)
	tmp := s.inventoryPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return 0, err
	}
	return len(inv), os.Rename(tmp, s.inventoryPath())
}
