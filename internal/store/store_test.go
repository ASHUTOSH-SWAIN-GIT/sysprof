package store

import (
	"math"
	"testing"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/syscalls"
)

func entry(pid uint32, comm string, nr uint32, count uint64) model.Entry {
	e := model.Entry{PID: pid, Comm: comm, Syscall: nr, Count: count, TotalNs: count * 1500}
	e.Hist[10] = count
	return e
}

func TestRateAndFilter(t *testing.T) {
	s := New(Filter{Comm: "nginx"}, 10)
	t0 := time.Unix(1000, 0)
	s.Update([]model.Entry{entry(1, "nginx", 0, 100), entry(2, "other", 0, 999)}, t0)
	s.Update([]model.Entry{entry(1, "nginx", 0, 300), entry(2, "other", 0, 5000)}, t0.Add(2*time.Second))

	snap := s.Latest()
	if len(snap.Processes) != 1 || snap.Processes[0].PID != 1 {
		t.Fatalf("filter failed: %+v", snap.Processes)
	}
	// 200 new calls over 2s
	if snap.Rate != 100 {
		t.Fatalf("rate = %v, want 100", snap.Rate)
	}
	if got := len(s.History()); got != 1 {
		t.Fatalf("history len = %d, want 1 (first reading has no interval)", got)
	}
}

func TestCounterResetTreatedAsNew(t *testing.T) {
	s := New(Filter{}, 10)
	t0 := time.Unix(1000, 0)
	s.Update([]model.Entry{entry(1, "a", 0, 500)}, t0)
	s.Update([]model.Entry{entry(1, "a", 0, 50)}, t0.Add(time.Second)) // pid reused
	if got := s.Latest().Rate; got != 50 {
		t.Fatalf("rate = %v, want 50", got)
	}
}

func TestCategoryAggregation(t *testing.T) {
	s := New(Filter{}, 10)
	t0 := time.Unix(1000, 0)
	readNr, _ := syscalls.Number("read")
	futexNr, _ := syscalls.Number("futex")
	entries := []model.Entry{entry(1, "a", readNr, 100), entry(1, "a", futexNr, 50)}
	s.Update(entries, t0)
	s.Update(entries, t0.Add(time.Second))

	snap := s.Latest()
	cats := map[string]model.CategoryStat{}
	var share float64
	for _, c := range snap.Categories {
		cats[c.Name] = c
		share += c.Share
	}
	if cats[syscalls.CategoryFile].Count != 100 || cats[syscalls.CategoryFile].TotalNs != 100*1500 {
		t.Fatalf("file category = %+v", cats[syscalls.CategoryFile])
	}
	if cats[syscalls.CategorySync].Count != 50 {
		t.Fatalf("sync category = %+v", cats[syscalls.CategorySync])
	}
	if math.Abs(share-1) > 1e-9 {
		t.Fatalf("shares sum to %v, want 1", share)
	}
	for _, st := range snap.Syscalls {
		if st.Name == "read" && st.Category != syscalls.CategoryFile {
			t.Fatalf("read category = %q", st.Category)
		}
	}
}

func TestDetectAnomalies(t *testing.T) {
	prior := make([]model.HistoryPoint, 6)
	for i := range prior {
		prior[i] = model.HistoryPoint{Syscalls: map[string]model.Latency{
			"read":  {Count: 100, P95Ns: 100_000},
			"write": {Count: 100, P95Ns: 100_000},
			"fsync": {Count: 100, P95Ns: 100_000},
		}}
	}
	cur := model.HistoryPoint{Time: time.Unix(2000, 0), Syscalls: map[string]model.Latency{
		"read":  {Count: 100, P95Ns: 300_000},
		"write": {Count: 100, P95Ns: 120_000},
		"fsync": {Count: 3, P95Ns: 900_000},
	}}

	got := detectAnomalies(cur, prior)
	if len(got) != 1 || got[0].Name != "read" {
		t.Fatalf("anomalies = %+v, want only read", got)
	}
	if got[0].BaseNs != 100_000 || math.Abs(got[0].Ratio-3) > 1e-9 {
		t.Fatalf("anomaly = %+v", got[0])
	}
	if detectAnomalies(cur, prior[:4]) != nil {
		t.Fatal("too few baseline points should not flag anything")
	}
}
