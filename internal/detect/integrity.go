package detect

import "fmt"

// FileIntegrityDetector translates hostsource's file_modified/file_deleted
// Events into Findings. All the actual detection work (baseline tracking,
// hashing) happens in the source; this detector is a thin, deliberately
// unconditional translator -- anything hostsource decided was worth an
// Event for is worth an alert, since it already applied the cheap
// precheck before ever emitting one.
type FileIntegrityDetector struct {
	verify PackageVerifier
}

// PackageVerifier tells whether a package manager owns a file and what SHA-256 it recorded for it.
type PackageVerifier interface {
	Expected(path string) (pkg, sha string, owned bool)
}

func NewFileIntegrityDetector() *FileIntegrityDetector { return &FileIntegrityDetector{} }

// NewPackageAwareFileIntegrityDetector also asks the package database: a changed file that now matches what its package
// shipped is a package update (info); one that a package owns but that differs from the record, or that no package owns,
// stays critical.
func NewPackageAwareFileIntegrityDetector(v PackageVerifier) *FileIntegrityDetector {
	return &FileIntegrityDetector{verify: v}
}

func (d *FileIntegrityDetector) ID() string { return "file-integrity" }

func (d *FileIntegrityDetector) Inspect(e Event) []Finding {
	switch e.Kind {
	case "file_modified":
		if d.verify != nil {
			if pkg, sha, owned := d.verify.Expected(e.Fields["path"]); owned {
				if sha != "" && sha == e.Fields["new_hash"] {
					return []Finding{{DetectorID: d.ID(), Severity: SeverityInfo,
						Summary: fmt.Sprintf("%s changed and now matches package %s (a package update)", e.Fields["path"], pkg), Event: e}}
				}
				if sha != "" {
					return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical,
						Summary: fmt.Sprintf("%s differs from what package %s shipped (not a package update)", e.Fields["path"], pkg), Event: e}}
				}
			}
		}
		return []Finding{{
			DetectorID: d.ID(),
			Severity:   SeverityCritical,
			Summary:    fmt.Sprintf("watched file changed unexpectedly: %s", e.Fields["path"]),
			Event:      e,
		}}
	case "file_deleted":
		return []Finding{{
			DetectorID: d.ID(),
			Severity:   SeverityCritical,
			Summary:    fmt.Sprintf("watched file was deleted: %s", e.Fields["path"]),
			Event:      e,
		}}
	default:
		return nil
	}
}
