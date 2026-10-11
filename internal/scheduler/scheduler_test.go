package scheduler

import "testing"

func TestJitterStats(t *testing.T) {
	avg, p99, max := jitterStats([]float64{1000, 2000, 3000, 100000})
	if max != 100 || p99 != 3 || avg != 26.5 {
		t.Fatalf("avg=%v p99=%v max=%v", avg, p99, max)
	}
	if a, p, m := jitterStats(nil); a != 0 || p != 0 || m != 0 {
		t.Fatal("empty input should be zero")
	}
}

func TestFakePolicyReducesJitter(t *testing.T) {
	f := NewFake()
	f.Stress()
	f.SetPolicy(PolicyStandard)
	std := f.State().Jitter.P99Us
	f.SetPolicy(PolicyInteractive)
	fast := f.State().Jitter.P99Us
	if fast >= std {
		t.Fatalf("interactive p99 %v should be below standard %v", fast, std)
	}
	if f.SetPolicy("bogus") == nil {
		t.Fatal("unknown policy accepted")
	}
}
