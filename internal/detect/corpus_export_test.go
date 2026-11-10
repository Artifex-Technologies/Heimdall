package detect

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"strconv"
	"testing"
)

// The regex differential corpus for the Rust port (rust/heimdall/tests/regex_corpus.rs): every text with what the Go
// detectors make of it. Go's \b, \s, \d and \w are ASCII and Rust's Unicode-aware, and Go reads a stray byte as U+FFFD, so
// the Rust port must show it finds exactly the same on texts built to tell them apart.
//
//	HEIMDALL_REGEX_CORPUS=out.jsonl HEIMDALL_REGEX_PER=400 go test ./internal/detect -run TestExportRegexCorpus
//
// HEIMDALL_REGEX_REPO=1 adds the repository's own files, as TestPrefilteredDetectorsMatchTheOldOnes uses. The committed
// copy (testdata/parity/regex-corpus.jsonl) is the made-up texts at 40 per pattern.
func TestExportRegexCorpus(t *testing.T) {
	out := os.Getenv("HEIMDALL_REGEX_CORPUS")
	if out == "" {
		t.Skip("HEIMDALL_REGEX_CORPUS not set")
	}
	per := 40
	if v, err := strconv.Atoi(os.Getenv("HEIMDALL_REGEX_PER")); err == nil && v > 0 {
		per = v
	}
	corpus := hostileTexts(rand.New(rand.NewSource(20261110)), per)
	if os.Getenv("HEIMDALL_REGEX_REPO") == "1" {
		corpus = append(repoTexts(t), corpus...)
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	inj, cred, uni := NewInjectionDetector(), NewCredentialDetector(), NewUnicodeDetector()
	type line struct {
		Hex       string   `json:"hex"`
		Injection string   `json:"injection"`
		Cred      bool     `json:"credential"`
		Unicode   string   `json:"unicode"`
		Redact    string   `json:"redact"`
		Matches   []string `json:"matches"`
	}
	hits := 0
	for _, text := range corpus {
		e := Event{Text: text}
		l := line{Hex: hex.EncodeToString([]byte(text)), Redact: RedactCredentials(text), Matches: CredentialMatches(text)}
		if f := inj.Inspect(e); len(f) > 0 {
			l.Injection = f[0].Summary
		}
		l.Cred = len(cred.Inspect(e)) > 0
		if f := uni.Inspect(e); len(f) > 0 {
			l.Unicode = f[0].Summary
		}
		if l.Injection != "" || l.Cred || l.Unicode != "" {
			hits++
		}
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d texts, %d with a finding, written to %s", len(corpus), hits, out)
}
