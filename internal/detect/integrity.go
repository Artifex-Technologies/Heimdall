package detect

import "fmt"

// FileIntegrityDetector translates hostsource's file_modified/file_deleted
// Events into Findings. All the actual detection work (baseline tracking,
// hashing) happens in the source; this detector is a thin, deliberately
// unconditional translator -- anything hostsource decided was worth an
// Event for is worth an alert, since it already applied the cheap
// precheck before ever emitting one.
type FileIntegrityDetector struct{}

func NewFileIntegrityDetector() *FileIntegrityDetector { return &FileIntegrityDetector{} }

func (d *FileIntegrityDetector) ID() string { return "file-integrity" }

func (d *FileIntegrityDetector) Inspect(e Event) []Finding {
	switch e.Kind {
	case "file_modified":
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
