package sockbypass

import (
	"context"
	"testing"
	"time"
)

func TestSummarize(t *testing.T) {
	lat := []int64{1000, 2000, 3000, 4000, 100000}
	d := summarize(lat, time.Second)
	if d.Rounds != 5 || d.P50Ns != 3000 || d.P99Ns != 4000 {
		t.Fatalf("unexpected dist: %+v", d)
	}
	if g := gain(Dist{MeanNs: 100}, Dist{MeanNs: 40}); g != 60 {
		t.Fatalf("gain = %v, want 60", g)
	}
}

func TestPingPongOverLoopback(t *testing.T) {
	d, err := runPingPong(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	if d.Rounds != 200 || d.MeanNs <= 0 {
		t.Fatalf("unexpected dist: %+v", d)
	}
}

func TestValidateRounds(t *testing.T) {
	if n, _ := ValidateRounds(0); n != DefaultBenchRounds {
		t.Fatalf("default = %d", n)
	}
	if _, err := ValidateRounds(MaxBenchRounds + 1); err == nil {
		t.Fatal("limit not enforced")
	}
}

func TestFakeBenchmarkShowsGain(t *testing.T) {
	f := NewFake()
	res, err := f.Benchmark(context.Background(), 1000)
	if err != nil || !res.Simulated || res.GainPercent <= 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if f.State().LastBench == nil {
		t.Fatal("last benchmark not kept")
	}
}
