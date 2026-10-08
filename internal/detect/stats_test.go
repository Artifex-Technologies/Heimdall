package detect

import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestOnlineStatsMeanAndStdDev(t *testing.T) {
	s := &OnlineStats{}
	for _, v := range []float64{1, 2, 3, 4, 5} {
		s.Add(v)
	}
	if s.Count() != 5 {
		t.Fatalf("expected count 5, got %d", s.Count())
	}
	if !almostEqual(s.Mean(), 3) {
		t.Fatalf("expected mean 3, got %v", s.Mean())
	}
	// Sample variance (Bessel's correction): ((1-3)^2+(2-3)^2+0+(4-3)^2+(5-3)^2)/(5-1) = 10/4 = 2.5
	wantStdDev := math.Sqrt(2.5)
	if !almostEqual(s.StdDev(), wantStdDev) {
		t.Fatalf("expected stddev %v, got %v", wantStdDev, s.StdDev())
	}
}

func TestOnlineStatsStdDevUndefinedBelowTwoSamples(t *testing.T) {
	s := &OnlineStats{}
	if s.StdDev() != 0 {
		t.Fatalf("expected 0 stddev with no samples, got %v", s.StdDev())
	}
	s.Add(42)
	if s.StdDev() != 0 {
		t.Fatalf("expected 0 stddev with one sample, got %v", s.StdDev())
	}
}

func TestOnlineStatsZScore(t *testing.T) {
	s := &OnlineStats{}
	for _, v := range []float64{10, 10, 10, 10} { // identical samples -> zero spread
		s.Add(v)
	}
	if z := s.ZScore(100); z != 0 {
		t.Fatalf("expected z-score 0 when stddev is 0, got %v", z)
	}

	s2 := &OnlineStats{}
	for _, v := range []float64{1, 2, 3, 4, 5} {
		s2.Add(v)
	}
	// mean=3, stddev=sqrt(2.5)=1.5811...; z-score of 3 (the mean) is 0.
	if z := s2.ZScore(3); !almostEqual(z, 0) {
		t.Fatalf("expected z-score 0 at the mean, got %v", z)
	}
}
