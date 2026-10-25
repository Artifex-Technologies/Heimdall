package immunity

import (
	"context"
	"fmt"
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
	if r.Infected {
		return r.Signature, nil
	}
	return "", nil
}
