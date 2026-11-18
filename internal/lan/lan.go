// Package lan keeps the list of devices on the home network: what each one is (maker from its hardware address, the name it
// announces or the router gave it, the services it offers), when it first showed up and when it was last seen, and a record of
// every device that is new. Settings shows the list; heimdalld raises an alert for each new device.
//
// It runs as its own short-lived process (heimdall-lan-scan.service, as the heimdall user), never inside heimdalld, which stays
// off the network. And it runs only on a network the owner marked trusted (heimdall-wifi-guard trust) whose router is the one
// recorded then: looking around someone else's network is not ours to do.
package lan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Device is one device on a network, keyed by its hardware address.
type Device struct {
	MAC    string   `json:"mac"`
	IP     string   `json:"ip"`
	Name   string   `json:"name,omitempty"`  // the best name found: announced, from the router, or from Windows networking
	Names  []string `json:"names,omitempty"` // every name found, best first
	Vendor string   `json:"vendor,omitempty"`
	Model  string   `json:"model,omitempty"`
	Kind   string   `json:"kind"` // router, this, tv, speaker, printer, phone, computer, console, smart, private, other
	// OwnerKind is what the owner said the device is (KindsFile), filled in when the list is read for Settings and `lan list`;
	// a scan never sets it and Kind stays the guess.
	OwnerKind  string    `json:"owner_kind,omitempty"`
	Services   []string  `json:"services,omitempty"`
	PrivateMAC bool      `json:"private_mac,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Network is one trusted network's devices.
type Network struct {
	UUID      string    `json:"uuid"` // NetworkManager's connection
	SSID      string    `json:"ssid"`
	FirstScan time.Time `json:"first_scan"`
	LastScan  time.Time `json:"last_scan"`
	Devices   []Device  `json:"devices"`
}

// Store is the whole file (devices.json).
type Store struct {
	Networks []Network `json:"networks"`
	// Status says why the last scan did or did not look (for Settings): "scanned", "not_trusted", "not_home" (trusted, but not as
	// the home network), "router_changed", "offline".
	Status     string    `json:"status"`
	StatusUUID string    `json:"status_uuid,omitempty"`
	StatusTime time.Time `json:"status_time"`
}

// MaxDevices bounds one network's list; the devices seen longest ago go first.
const MaxDevices = 512

// Load reads the store; a missing file is an empty store.
func Load(path string) (*Store, error) {
	s := &Store{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	return s, json.Unmarshal(b, s)
}

// Save writes the store whole (write and rename, so a reader never sees half a file).
func (s *Store) Save(path string) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) network(uuid, ssid string) *Network {
	for i := range s.Networks {
		if s.Networks[i].UUID == uuid {
			if ssid != "" {
				s.Networks[i].SSID = ssid
			}
			return &s.Networks[i]
		}
	}
	s.Networks = append(s.Networks, Network{UUID: uuid, SSID: ssid})
	return &s.Networks[len(s.Networks)-1]
}

// Merge records the devices one scan saw and returns those that are new. The first scan of a network only learns: every device
// already there is the owner's own or was there before Heimdall looked, and an alert for each would be noise.
func (n *Network) Merge(seen []Device, now time.Time) []Device {
	first := n.FirstScan.IsZero()
	if first {
		n.FirstScan = now
	}
	n.LastScan = now
	index := map[string]int{}
	for i, d := range n.Devices {
		index[d.MAC] = i
	}
	var fresh []Device
	for _, d := range seen {
		d.LastSeen = now
		if i, ok := index[d.MAC]; ok {
			old := n.Devices[i]
			d.FirstSeen = old.FirstSeen
			// a scan that missed an announcement keeps what earlier scans found
			if d.Name == "" {
				d.Name, d.Names = old.Name, old.Names
			}
			if d.Vendor == "" {
				d.Vendor = old.Vendor
			}
			if d.Model == "" {
				d.Model = old.Model
			}
			if len(d.Services) == 0 {
				d.Services = old.Services
			}
			if d.Kind == "other" || d.Kind == "private" {
				if old.Kind != "other" && old.Kind != "private" && old.Kind != "" {
					d.Kind = old.Kind
				}
			}
			n.Devices[i] = d
			continue
		}
		d.FirstSeen = now
		n.Devices = append(n.Devices, d)
		index[d.MAC] = len(n.Devices) - 1
		if !first && d.Kind != "this" {
			fresh = append(fresh, d)
		}
	}
	sort.SliceStable(n.Devices, func(i, j int) bool { return n.Devices[i].LastSeen.After(n.Devices[j].LastSeen) })
	if len(n.Devices) > MaxDevices {
		n.Devices = n.Devices[:MaxDevices]
	}
	return fresh
}

// NewDevice is one line of events.jsonl, which heimdalld follows (internal/sources/lansource).
type NewDevice struct {
	Time   time.Time `json:"time"`
	SSID   string    `json:"ssid"`
	Device Device    `json:"device"`
	// Change is set on a known device's address taken over (Takeovers): "address_taken", with the hardware address and name
	// that had the address in the last scan, and the other address the new hardware address answers for at the same time.
	Change  string `json:"change,omitempty"`
	WasMAC  string `json:"was_mac,omitempty"`
	WasName string `json:"was_name,omitempty"`
	OtherIP string `json:"other_ip,omitempty"`
}

// Takeovers finds known devices whose address another device now answers for: an address that a known device had in the
// last scan answers with another hardware address, that hardware address answers for another address in the same scan, and
// the device that had it is not seen anywhere. One device answering for two addresses at once while the owner of one is gone
// is what ARP spoofing a device looks like (someone placing themselves between it and the rest of the network). A device that
// simply got a new address, or a new device given a freed address, answers for one address only. Call before Merge.
func Takeovers(n *Network, ssid string, seen []Device, now time.Time) []NewDevice {
	if n.FirstScan.IsZero() {
		return nil
	}
	ipsOf := map[string][]string{}
	for _, d := range seen {
		ipsOf[d.MAC] = append(ipsOf[d.MAC], d.IP)
	}
	prev := map[string]Device{}
	for _, d := range n.Devices {
		if d.LastSeen.Equal(n.LastScan) {
			prev[d.IP] = d
		}
	}
	var out []NewDevice
	for _, d := range seen {
		old, ok := prev[d.IP]
		if !ok || old.MAC == d.MAC || len(ipsOf[d.MAC]) < 2 || len(ipsOf[old.MAC]) > 0 {
			continue
		}
		other := ""
		for _, ip := range ipsOf[d.MAC] {
			if ip != d.IP {
				other = ip
				break
			}
		}
		out = append(out, NewDevice{Time: now, SSID: ssid, Device: d, Change: "address_taken", WasMAC: old.MAC, WasName: old.Name, OtherIP: other})
	}
	return out
}

// appendChanges adds one line per known device's address taken over.
func appendChanges(path string, changes []NewDevice) error {
	if len(changes) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, c := range changes {
		b, _ := json.Marshal(c)
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// appendEvents adds one line per new device.
func appendEvents(path, ssid string, devs []Device, now time.Time) error {
	if len(devs) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, d := range devs {
		b, _ := json.Marshal(NewDevice{Time: now, SSID: ssid, Device: d})
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// kindOf guesses what a device is from what it offers and who made it. Settings shows it as an icon and a word; it is a guess.
func kindOf(d Device) string {
	has := func(t ...string) bool {
		for _, s := range d.Services {
			for _, x := range t {
				if s == x {
					return true
				}
			}
		}
		return false
	}
	text := strings.ToLower(d.Name + " " + d.Model + " " + d.Vendor)
	tvMaker := false
	for _, m := range []string{"samsung", "lg electronics", "sony", "tcl", "vizio", "roku", "hisense", "amazon", "nvidia", "philips", "sharp"} {
		if strings.Contains(text, m) {
			tvMaker = true
		}
	}
	switch {
	case has("_ipp._tcp", "_printer._tcp", "_ipps._tcp", "_pdl-datastream._tcp"):
		return "printer"
	case has("_googlecast._tcp", "_amzn-wplay._tcp", "_androidtvremote2._tcp") || strings.Contains(text, " tv") ||
		strings.HasPrefix(text, "tv") || strings.Contains(text, "fire tv") || strings.Contains(text, "roku") ||
		(has("_airplay._tcp") && tvMaker):
		if has("_googlecast._tcp") && strings.Contains(text, "speaker") || strings.Contains(text, "nest audio") || strings.Contains(text, "home mini") {
			return "speaker"
		}
		return "tv"
	case has("_sonos._tcp", "_spotify-connect._tcp", "_raop._tcp") && !has("_workstation._tcp", "_companion-link._tcp", "_smb._tcp"):
		return "speaker"
	case strings.Contains(text, "iphone") || strings.Contains(text, "ipad") || strings.Contains(text, "android") ||
		strings.Contains(text, "galaxy") || strings.Contains(text, "pixel"):
		return "phone"
	case has("_workstation._tcp", "_smb._tcp", "_ssh._tcp", "_companion-link._tcp") || strings.Contains(text, "macbook") ||
		strings.Contains(text, "desktop") || strings.Contains(text, "laptop"):
		return "computer"
	case strings.Contains(text, "xbox") || strings.Contains(text, "playstation") || strings.Contains(text, "nintendo"):
		return "console"
	case strings.Contains(text, "espressif") || strings.Contains(text, "tuya") || strings.Contains(text, "shelly") ||
		strings.Contains(text, "wyze") || strings.Contains(text, "ring") || strings.Contains(text, "ecobee") ||
		strings.Contains(text, "nest labs") || strings.Contains(text, "signify") || has("_hap._tcp", "_matter._tcp"):
		return "smart" // smart-home gadgets: plugs, bulbs, clocks, cameras, thermostats
	case d.PrivateMAC:
		return "private" // a made-up address: almost always a phone, tablet or laptop
	}
	return "other"
}

// KindsFile, in the state directory, holds the owner's corrections of the guess: {"MAC": "kind"} (upper-case hardware
// addresses). `heimdalld lan kind` writes it as root (Settings runs it through pkexec); the scan never touches it.
const KindsFile = "kinds.json"

// OwnerKinds are the kinds the owner may give a device. "this" and "private" are only ever the list's own words.
var OwnerKinds = []string{"tv", "phone", "computer", "console", "speaker", "printer", "smart", "router", "other"}

var macForm = regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5}$`)

func ownerKind(k string) bool {
	for _, o := range OwnerKinds {
		if k == o {
			return true
		}
	}
	return false
}

// upperASCII upper-cases a-z only, so a hardware address matches whatever case the list or the owner wrote it in.
func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// LoadKinds reads the owner's corrections. A missing or damaged file is none; an entry that is not an upper-case hardware
// address with one of OwnerKinds is left out.
func LoadKinds(path string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := map[string]string{}
	for m, k := range raw {
		if s, ok := k.(string); ok && macForm.MatchString(m) && ownerKind(s) {
			out[m] = s
		}
	}
	return out
}

// ApplyKinds fills in each device's OwnerKind from the owner's corrections.
func (s *Store) ApplyKinds(kinds map[string]string) {
	for i := range s.Networks {
		for j := range s.Networks[i].Devices {
			d := &s.Networks[i].Devices[j]
			d.OwnerKind = kinds[upperASCII(d.MAC)]
		}
	}
}

// List is the device list as the API serves it: the store in dir with the owner's kinds filled in, or {"status":
// "unreadable"} when the store cannot be read.
func List(dir string) *Store {
	st, err := Load(filepath.Join(dir, "devices.json"))
	if err != nil {
		return &Store{Status: "unreadable"}
	}
	st.ApplyKinds(LoadKinds(filepath.Join(dir, KindsFile)))
	return st
}

// SetKind records what the owner says a device is; "guess" takes the correction away, so the list's guess shows again. It
// returns the address as stored. The file is written whole (write and rename), readable by all who can reach the directory.
func SetKind(path, mac, kind string) (string, error) {
	m := upperASCII(mac)
	if !macForm.MatchString(m) {
		return "", fmt.Errorf("%q is not a hardware address (six pairs of hex digits with colons): nothing changed", mac)
	}
	if kind != "guess" && !ownerKind(kind) {
		return "", fmt.Errorf("unknown kind %q (%s, or guess): nothing changed", kind, strings.Join(OwnerKinds, ", "))
	}
	kinds := LoadKinds(path)
	if kinds == nil {
		kinds = map[string]string{}
	}
	if kind == "guess" {
		delete(kinds, m)
	} else {
		kinds[m] = kind
	}
	b, _ := json.Marshal(kinds) // keys sorted
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return "", err
	}
	return m, os.Rename(tmp, path)
}

// statePaths are the files in the state directory.
func statePaths(dir string) (store, events string) {
	return filepath.Join(dir, "devices.json"), filepath.Join(dir, "events.jsonl")
}
