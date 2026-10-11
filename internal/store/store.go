// Package store turns cumulative collector entries into snapshots and keeps
// a short rolling history. The CLI and the HTTP API both read from it.
package store

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/collector"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/syscalls"
)

// Filter restricts which entries are counted. Zero values match everything.
type Filter struct {
	PID     uint32
	Comm    string // substring match
	Syscall string // exact name
}

func (f Filter) match(e model.Entry, name string) bool {
	if f.PID != 0 && e.PID != f.PID {
		return false
	}
	if f.Comm != "" && !strings.Contains(e.Comm, f.Comm) {
		return false
	}
	if f.Syscall != "" && name != f.Syscall {
		return false
	}
	return true
}

type key struct{ pid, nr uint32 }

// Store is safe for concurrent use.
type Store struct {
	filter   Filter
	maxHist  int
	mu       sync.RWMutex
	prev     map[key]model.Entry
	prevTime time.Time
	latest   model.Snapshot
	history  []model.HistoryPoint
	subs     map[chan struct{}]struct{}
}

// New keeps up to maxHistory intervals (e.g. 300 at 1s is 5 minutes).
func New(f Filter, maxHistory int) *Store {
	return &Store{
		filter:  f,
		maxHist: maxHistory,
		prev:    map[key]model.Entry{},
		subs:    map[chan struct{}]struct{}{},
	}
}

// Run reads the collector every interval until ctx is cancelled.
func (s *Store) Run(ctx context.Context, c collector.Collector, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		entries, err := c.Read()
		if err != nil {
			log.Printf("collector read: %v", err)
		} else {
			s.Update(entries, time.Now())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Update ingests a cumulative reading taken at now.
func (s *Store) Update(entries []model.Entry, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	elapsed := now.Sub(s.prevTime).Seconds()
	first := s.prevTime.IsZero()

	bySys := map[uint32]*model.SyscallStat{}
	delta := map[uint32]*[model.HistBuckets]uint64{} // interval histograms per syscall
	deltaCnt := map[uint32]uint64{}
	byProc := map[uint32]*model.ProcessStat{}
	procSys := map[uint32]map[uint32]uint64{} // pid -> syscall -> total ns
	procDelta := map[uint32]uint64{}
	cur := make(map[key]model.Entry, len(entries))
	var totalDelta uint64

	for _, e := range entries {
		name := syscalls.Name(e.Syscall)
		if !s.filter.match(e, name) {
			continue
		}
		k := key{e.PID, e.Syscall}
		cur[k] = e

		st := bySys[e.Syscall]
		if st == nil {
			st = &model.SyscallStat{Name: name, Nr: e.Syscall, Blocking: syscalls.IsBlocking(name), Hist: make([]uint64, model.HistBuckets)}
			bySys[e.Syscall] = st
			delta[e.Syscall] = new([model.HistBuckets]uint64)
		}
		st.Count += e.Count
		st.TotalNs += e.TotalNs
		if e.MaxNs > st.MaxNs {
			st.MaxNs = e.MaxNs
		}
		for i, c := range e.Hist {
			st.Hist[i] += c
		}

		p := byProc[e.PID]
		if p == nil {
			p = &model.ProcessStat{PID: e.PID, Comm: e.Comm}
			byProc[e.PID] = p
			procSys[e.PID] = map[uint32]uint64{}
		}
		p.Count += e.Count
		p.TotalNs += e.TotalNs
		if !st.Blocking {
			procSys[e.PID][e.Syscall] += e.TotalNs
		}

		// Interval delta against the previous reading. If counters went
		// down (pid reused, map entry evicted) treat the entry as new.
		pe, ok := s.prev[k]
		if !ok || e.Count < pe.Count {
			pe = model.Entry{}
		}
		for i := range e.Hist {
			d := e.Hist[i] - pe.Hist[i]
			delta[e.Syscall][i] += d
		}
		dc := e.Count - pe.Count
		deltaCnt[e.Syscall] += dc
		procDelta[e.PID] += dc
		totalDelta += dc
	}

	snap := model.Snapshot{Time: now}
	hp := model.HistoryPoint{Time: now, Syscalls: map[string]model.Latency{}}
	if !first && elapsed > 0 {
		snap.Rate = float64(totalDelta) / elapsed
		hp.Rate = snap.Rate
	}

	for nr, st := range bySys {
		if st.Count > 0 {
			st.AvgNs = float64(st.TotalNs) / float64(st.Count)
		}
		st.P50Ns = model.Percentile(st.Hist, 0.50)
		st.P95Ns = model.Percentile(st.Hist, 0.95)
		st.P99Ns = model.Percentile(st.Hist, 0.99)
		if !first && elapsed > 0 {
			st.Rate = float64(deltaCnt[nr]) / elapsed
		}
		if deltaCnt[nr] > 0 && !first {
			h := delta[nr][:]
			hp.Syscalls[st.Name] = model.Latency{
				Count: deltaCnt[nr],
				P50Ns: model.Percentile(h, 0.50),
				P95Ns: model.Percentile(h, 0.95),
				P99Ns: model.Percentile(h, 0.99),
			}
		}
		snap.Syscalls = append(snap.Syscalls, *st)
	}
	sort.Slice(snap.Syscalls, func(i, j int) bool { return snap.Syscalls[i].TotalNs > snap.Syscalls[j].TotalNs })

	for pid, p := range byProc {
		if p.Count > 0 {
			p.AvgNs = float64(p.TotalNs) / float64(p.Count)
		}
		if !first && elapsed > 0 {
			p.Rate = float64(procDelta[pid]) / elapsed
		}
		var best uint64
		for nr, ns := range procSys[pid] {
			if ns > best {
				best = ns
				p.TopSyscall = syscalls.Name(nr)
			}
		}
		snap.Processes = append(snap.Processes, *p)
	}
	sort.Slice(snap.Processes, func(i, j int) bool { return snap.Processes[i].TotalNs > snap.Processes[j].TotalNs })

	s.prev, s.prevTime, s.latest = cur, now, snap
	if !first {
		s.history = append(s.history, hp)
		if len(s.history) > s.maxHist {
			s.history = s.history[len(s.history)-s.maxHist:]
		}
	}
	for ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default: // slow subscriber, it will catch up on the next tick
		}
	}
}

// Latest returns the most recent snapshot.
func (s *Store) Latest() model.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest
}

// History returns a copy of the rolling history, oldest first.
func (s *Store) History() []model.HistoryPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.HistoryPoint(nil), s.history...)
}

// Subscribe returns a channel that is signalled after every update, and a
// function to cancel the subscription.
func (s *Store) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}
}
