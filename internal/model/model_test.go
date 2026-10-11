package model

import "testing"

func TestPercentile(t *testing.T) {
	h := make([]uint64, HistBuckets)
	if got := Percentile(h, 0.5); got != 0 {
		t.Fatalf("empty histogram: got %v, want 0", got)
	}
	h[10] = 100 // all samples in [1024, 2048)
	p50 := Percentile(h, 0.5)
	if p50 < 1024 || p50 > 2048 {
		t.Fatalf("p50 %v outside bucket [1024,2048)", p50)
	}
	h[20] = 1 // one outlier in [2^20, 2^21)
	if p99, p100 := Percentile(h, 0.99), Percentile(h, 1.0); p99 >= 2048 || p100 < 1<<20 {
		t.Fatalf("p99=%v p100=%v: outlier should only affect the top", p99, p100)
	}
}
