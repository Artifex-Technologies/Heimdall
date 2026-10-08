package detect

import "math"

// OnlineStats tracks a running mean and variance via Welford's algorithm:
// O(1) memory and O(1) work per sample, no history array to keep or
// prune. This is the whole of Phase 5's "pattern recognition" — genuinely
// simple streaming statistics, not a model, and described that way on
// purpose (see docs/ARCHITECTURE.md's Phase 5 section and
// docs/REFERENCES.md) rather than overclaimed as ML.
type OnlineStats struct {
	count int
	mean  float64
	m2    float64 // sum of squared differences from the running mean
}

// Add folds x into the running statistics.
func (s *OnlineStats) Add(x float64) {
	s.count++
	delta := x - s.mean
	s.mean += delta / float64(s.count)
	delta2 := x - s.mean
	s.m2 += delta * delta2
}

func (s *OnlineStats) Count() int { return s.count }

func (s *OnlineStats) Mean() float64 { return s.mean }

// StdDev is the sample standard deviation (Bessel's correction, n-1).
// Zero until at least two samples have been added.
func (s *OnlineStats) StdDev() float64 {
	if s.count < 2 {
		return 0
	}
	return math.Sqrt(s.m2 / float64(s.count-1))
}

// ZScore reports how many standard deviations x is from the current
// running mean. Zero when there isn't yet a meaningful spread to compare
// against (fewer than 2 samples, or every sample so far identical).
func (s *OnlineStats) ZScore(x float64) float64 {
	sd := s.StdDev()
	if sd == 0 {
		return 0
	}
	return (x - s.mean) / sd
}
