package store

import (
	"testing"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
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
