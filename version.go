// Package heimdall holds what belongs to the repository as a whole: Heimdall's version.
package heimdall

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version is Heimdall's own version: the VERSION file at the top of this repository, read when the program is built
// (Labyrinth_OS's docs/VERSIONING.md; its scripts/release.sh writes the file). `heimdalld version` prints it; the Rust
// heimdalld reads the same file.
var Version = strings.TrimSpace(versionFile)
