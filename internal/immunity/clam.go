package immunity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/scan"
)

// ClamAV is the reference scanner: ClamAV's signature for a file, "" when it does not know it.
func ClamAV(path string) (string, error) {
	c := scan.NewClamAV()
	if !c.Available() {
		return "", fmt.Errorf("ClamAV is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r, err := c.ScanFile(ctx, path)
	if err != nil {
		return "", err
	}
	return referenceAnswer(r)
}

// referenceAnswer reads ClamAV's answer: a signature, "" for a file it does not know, and an error for one it stopped
// at a limit with (Heuristics.Limits.Exceeded.*): that file was not fully scanned, and ClamAV does not know it either way.
func referenceAnswer(r scan.Result) (string, error) {
	if !r.Infected {
		return "", nil
	}
	if strings.HasPrefix(r.Signature, "Heuristics.Limits.Exceeded") {
		return "", fmt.Errorf("not fully scanned: ClamAV stopped at a limit (%s)", r.Signature)
	}
	return r.Signature, nil
}
