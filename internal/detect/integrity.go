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
	trust  TrustJudge
}

// TrustJudge says whether a change to one of the AI agents' behaviour files was approved (signed by the owner, package trust):
// "approved", "unsigned" (with why), or "" when it has no say (trust off, or not one of its files).
type TrustJudge interface {
	Judge(path, newHash string, deleted bool) (verdict, why string)
}

// WithTrust makes the detector ask the signed list of approved files first.
func (d *FileIntegrityDetector) WithTrust(t TrustJudge) *FileIntegrityDetector {
	d.trust = t
	return d
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
	if d.trust != nil && (e.Kind == "file_modified" || e.Kind == "file_created" || e.Kind == "file_deleted") {
		switch verdict, why := d.trust.Judge(e.Fields["path"], e.Fields["new_hash"], e.Kind == "file_deleted"); verdict {
		case "approved":
			return []Finding{{DetectorID: d.ID(), Severity: SeverityInfo,
				Summary: fmt.Sprintf("%s: %s, approved (it matches the signed list)", e.Fields["path"], verb(e.Kind)), Event: e}}
		case "unsigned":
			return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical,
				Summary: fmt.Sprintf("%s: %s without approval (%s); it decides how an AI agent behaves", e.Fields["path"], verb(e.Kind), why), Event: e, Firm: true}}
		}
	}
	switch e.Kind {
	case "file_created":
		if d.verify != nil {
			if pkg, sha, owned := d.verify.Expected(e.Fields["path"]); owned && sha != "" && sha == e.Fields["new_hash"] {
				return []Finding{{DetectorID: d.ID(), Severity: SeverityInfo,
					Summary: fmt.Sprintf("a new file in a watched folder, installed by package %s: %s", pkg, e.Fields["path"]), Event: e}}
			}
		}
		return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical,
			Summary: fmt.Sprintf("a new file appeared in a watched folder: %s", e.Fields["path"]), Event: e}}
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

func verb(kind string) string {
	switch kind {
	case "file_created":
		return "new file"
	case "file_deleted":
		return "deleted"
	}
	return "changed"
}
