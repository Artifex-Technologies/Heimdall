package detect

// CrossViewDetector (HEI-50, R13 phase 2): something the system answers when asked directly but leaves out of its own
// lists, a process missing from /proc's listing or a socket missing from /proc/net, is what a rootkit does to hide.
// The source (the Rust daemon's sources/crossview.rs) reports only what stayed hidden over two looks.
type CrossViewDetector struct{}

func NewCrossViewDetector() *CrossViewDetector { return &CrossViewDetector{} }

func (d *CrossViewDetector) ID() string { return "crossview" }

func (d *CrossViewDetector) Inspect(e Event) []Finding {
	if e.Kind != "crossview" {
		return nil
	}
	return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Event: e,
		Summary: e.Text + ": the system answers for it when asked directly but leaves it out of its own list, which is how a rootkit hides what it runs"}}
}
