package immunity

// YARA rules from Limbo's analyses: immunity's next step after fingerprints (docs/IMMUNITY.md, "Rules"). A fingerprint
// catches exact copies; a rule built from what a sample contains catches its variants. Sarina drafts a rule from the
// analysis report, Heimdall checks its form and keeps it, root tests it against the stored sample (it must match) and the
// computer's own programs (it must match none), and only the owner approves it; then ClamAV loads it with its own database.
//
// Who writes what:
//   - drafts (DefaultRuleDrafts, heimdalld's folder): heimdalld, from POST /v1/rules/drafts; root adds test results.
//   - approved rules (/var/lib/clamav/heimdall-rule-<name>.yar): root only, by `heimdalld immunity rule approve`.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultRuleDrafts = "/var/lib/heimdall/rule-drafts.json"
	DefaultRulesDir   = "/var/lib/clamav"

	RuleDraft    = "draft"
	RuleTested   = "tested" // matched the sample and nothing else
	RuleFailed   = "failed" // did not match the sample, or matched the computer's own programs, or did not load
	RuleApproved = "approved"
	RuleRejected = "rejected"

	maxRule   = 16 << 10
	maxDrafts = 100
)

// DefaultFPRoots are the computer's own programs a rule is tested against: it must match none of them.
var DefaultFPRoots = []string{"/usr/bin", "/usr/local/bin", "/usr/lib/systemd"}

// Rule is one draft and what happened to it.
type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"` // the YARA rule's name; ClamAV reports YARA.<name>
	SampleSHA string    `json:"sample_sha256"`
	Text      string    `json:"text"`
	TextSHA   string    `json:"text_sha256"`
	Note      string    `json:"note,omitempty"` // the drafter's words (untrusted)
	UID       uint32    `json:"uid"`
	Time      time.Time `json:"time"`
	Status    string    `json:"status"`
	Test      *RuleTest `json:"test,omitempty"`
	Decided   time.Time `json:"decided,omitempty"`
	By        string    `json:"by,omitempty"`
	Installed string    `json:"installed,omitempty"`
}

// RuleTest is the result of a test, for the exact text tested.
type RuleTest struct {
	Time           time.Time `json:"time"`
	TextSHA        string    `json:"text_sha256"`
	MatchedSample  bool      `json:"matched_sample"`
	FalsePositives []string  `json:"false_positives,omitempty"` // at most 20 shown
	FPCount        int       `json:"fp_count"`
	Scanned        []string  `json:"scanned"`
	Error          string    `json:"error,omitempty"`
}

var (
	ruleNameRx = regexp.MustCompile(`(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)`)
	goodName   = regexp.MustCompile(`^Heimdall_[A-Za-z0-9_]{1,64}$`)
	forbidden  = regexp.MustCompile(`(?m)^\s*(import|include)\b`)
	shaRx      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// CheckRule checks a draft's form before it is kept: one rule, named Heimdall_..., with a condition, no import or include
// (an include would make ClamAV read another file), at most 16 KiB of printable text. It returns the rule's name.
func CheckRule(text string) (string, error) {
	if len(text) == 0 || len(text) > maxRule {
		return "", errors.New("a rule is 1 byte to 16 KiB")
	}
	for _, r := range text {
		if r == 0 || (r < 32 && r != '\n' && r != '\t' && r != '\r') {
			return "", errors.New("a rule is printable text")
		}
	}
	if forbidden.MatchString(text) {
		return "", errors.New("no import or include: a rule stands alone")
	}
	names := ruleNameRx.FindAllStringSubmatch(text, -1)
	if len(names) != 1 {
		return "", fmt.Errorf("exactly one rule per draft (found %d)", len(names))
	}
	name := names[0][1]
	if !goodName.MatchString(name) {
		return "", errors.New("the rule's name starts with Heimdall_ (letters, digits and _ after it, at most 64), so ClamAV's report says where it came from")
	}
	if !strings.Contains(text, "condition:") {
		return "", errors.New("a rule needs a condition")
	}
	return name, nil
}

// Rules is the drafts file.
type Rules struct {
	Path     string // DefaultRuleDrafts
	RulesDir string // where approved rules are installed (ClamAV's database folder)
}

func DefaultRules() Rules { return Rules{Path: DefaultRuleDrafts, RulesDir: DefaultRulesDir} }

var rulesMu sync.Mutex

// Load returns the drafts, newest last. Never follows a link: root reads this file from heimdalld's folder.
func (r Rules) Load() ([]Rule, error) {
	f, err := os.OpenFile(r.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rs []Rule
	b, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil, err
	}
	return rs, json.Unmarshal(b, &rs)
}

func (r Rules) save(rs []Rule) error {
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.Path), ".rule-drafts-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	_ = tmp.Chmod(0o640)
	// root writing into heimdalld's folder leaves the file to the folder's owner, or the daemon could no longer add drafts
	if fi, err := os.Stat(filepath.Dir(r.Path)); err == nil && os.Geteuid() == 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = tmp.Chown(int(st.Uid), int(st.Gid))
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), r.Path)
}

func textSHA(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

// Draft keeps a new draft (heimdalld, from the API). The same text for the same sample is not kept twice.
func (r Rules) Draft(sample, text, note string, uid uint32, now time.Time) (Rule, error) {
	if !shaRx.MatchString(sample) {
		return Rule{}, errors.New("sample_sha256: the held sample's 64-character SHA-256")
	}
	name, err := CheckRule(text)
	if err != nil {
		return Rule{}, err
	}
	if len(note) > 2000 {
		note = note[:2000]
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rs, err := r.Load()
	if err != nil {
		return Rule{}, err
	}
	sum := textSHA(text)
	for _, o := range rs {
		if o.SampleSHA == sample && o.TextSHA == sum {
			return o, nil
		}
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	d := Rule{ID: hex.EncodeToString(b), Name: name, SampleSHA: sample, Text: text, TextSHA: sum, Note: note, UID: uid, Time: now.UTC(), Status: RuleDraft}
	rs = append(rs, d)
	if len(rs) > maxDrafts {
		rs = rs[len(rs)-maxDrafts:]
	}
	return d, r.save(rs)
}

func (r Rules) update(id string, f func(*Rule) error) (Rule, error) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rs, err := r.Load()
	if err != nil {
		return Rule{}, err
	}
	for i := range rs {
		if rs[i].ID == id {
			if err := f(&rs[i]); err != nil {
				return rs[i], err
			}
			return rs[i], r.save(rs)
		}
	}
	return Rule{}, fmt.Errorf("no rule draft %q (heimdalld immunity rule list)", id)
}

// RuleScanner runs ClamAV with only the rule loaded: the paths it reports as matching. Errors only when the scan could not
// run (a file it could not read is not a match).
type RuleScanner func(ctx context.Context, rulePath string, paths []string) (matched []string, err error)

// ClamRuleScan is RuleScanner with clamscan: -d loads only the rule (seconds, not the full database), -r into folders.
func ClamRuleScan(ctx context.Context, rulePath string, paths []string) ([]string, error) {
	args := append([]string{"--no-summary", "--infected", "-r", "--max-filesize=200M", "--max-scansize=200M", "-d", rulePath, "--"}, paths...)
	cmd := exec.CommandContext(ctx, "clamscan", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var matched []string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasSuffix(line, " FOUND") {
			if i := strings.LastIndex(line, ": "); i > 0 {
				matched = append(matched, line[:i])
			}
		}
	}
	var ee *exec.ExitError
	if err != nil && !(errors.As(err, &ee) && (ee.ExitCode() == 1 || ee.ExitCode() == 2)) {
		return matched, err // 1: found, 2: some file could not be read; anything else: the scan did not run
	}
	return matched, nil
}

// Test (root) checks one draft: written with the sample into a fresh root-only folder, the rule must match the sample and
// none of the files under fpRoots. The result is kept with the exact text it was made for.
func (r Rules) Test(id string, s Store, fpRoots []string, scan RuleScanner, now time.Time) (Rule, error) {
	rs, err := r.Load()
	if err != nil {
		return Rule{}, err
	}
	var d *Rule
	for i := range rs {
		if rs[i].ID == id {
			d = &rs[i]
		}
	}
	if d == nil {
		return Rule{}, fmt.Errorf("no rule draft %q", id)
	}
	if _, err := CheckRule(d.Text); err != nil || textSHA(d.Text) != d.TextSHA {
		return Rule{}, errors.New("the draft changed or is malformed; draft it again")
	}
	work, err := os.MkdirTemp("", "heimdall-rule-")
	if err != nil {
		return Rule{}, err
	}
	defer os.RemoveAll(work)
	rule := filepath.Join(work, d.Name+".yar")
	if err := os.WriteFile(rule, []byte(d.Text), 0o600); err != nil {
		return Rule{}, err
	}
	sample := filepath.Join(work, "sample")
	if err := s.Extract(d.SampleSHA, sample); err != nil {
		return Rule{}, fmt.Errorf("the sample %s: %w", d.SampleSHA[:12], err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	t := &RuleTest{Time: now.UTC(), TextSHA: d.TextSHA, Scanned: fpRoots}
	if m, err := scan(ctx, rule, []string{sample}); err != nil {
		t.Error = err.Error()
	} else {
		t.MatchedSample = len(m) > 0
	}
	if t.Error == "" {
		fp, err := scan(ctx, rule, fpRoots)
		if err != nil {
			t.Error = err.Error()
		}
		t.FPCount = len(fp)
		if len(fp) > 20 {
			fp = fp[:20]
		}
		t.FalsePositives = fp
	}
	return r.update(id, func(x *Rule) error {
		x.Test = t
		x.Status = RuleFailed
		if t.Error == "" && t.MatchedSample && t.FPCount == 0 {
			x.Status = RuleTested
		}
		return nil
	})
}

// Approve (root, the owner) installs a draft that passed its test, for exactly the tested text, into ClamAV's database
// folder: from then on every ClamAV scan knows it.
func (r Rules) Approve(id, by string, now time.Time) (Rule, error) {
	return r.update(id, func(x *Rule) error {
		if x.Status != RuleTested || x.Test == nil || x.Test.TextSHA != textSHA(x.Text) || x.TextSHA != x.Test.TextSHA {
			return errors.New("only a draft that matched its sample and none of this computer's programs can be approved: sudo heimdalld immunity rule test " + x.ID)
		}
		if _, err := CheckRule(x.Text); err != nil {
			return err
		}
		dst := filepath.Join(r.RulesDir, "heimdall-rule-"+strings.ToLower(strings.TrimPrefix(x.Name, "Heimdall_"))+".yar")
		tmp, err := os.CreateTemp(r.RulesDir, ".heimdall-rule-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(x.Text); err != nil {
			tmp.Close()
			return err
		}
		_ = tmp.Chmod(0o644)
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmp.Name(), dst); err != nil {
			return err
		}
		x.Status, x.Decided, x.By, x.Installed = RuleApproved, now.UTC(), by, dst
		return nil
	})
}

// Reject marks a draft rejected; Forget also removes an installed rule.
func (r Rules) Reject(id, by string, now time.Time) (Rule, error) {
	return r.update(id, func(x *Rule) error {
		if x.Installed != "" {
			if err := os.Remove(x.Installed); err != nil && !os.IsNotExist(err) {
				return err
			}
			x.Installed = ""
		}
		x.Status, x.Decided, x.By = RuleRejected, now.UTC(), by
		return nil
	})
}

// RulesStamp changes whenever an approved rule is added, changed or removed, so a remembered scan of unchanged files is
// redone (scan.State.UseSignatures).
func RulesStamp(dir string) string {
	m, _ := filepath.Glob(filepath.Join(dir, "heimdall-rule-*.yar"))
	if len(m) == 0 {
		return "" // no rules: the stamp stays what it was before rules existed, so nothing is scanned again for nothing
	}
	h := sha256.New()
	for _, p := range m {
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(h, "%s %d %d\n", p, fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
