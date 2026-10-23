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

// catAgg accumulates one syscall category across all processes and syscalls.
type catAgg struct {
	count    uint64
	deltaCnt uint64
	totalNs  uint64
	hist     []uint64
}

const (
	spikeFactor        = 2.0
	spikeMinDeltaNs    = 25_000
	spikeMinCount      = 10
	spikeMinBasePoints = 5
	spikeBaseWindow    = 30
	spikeMaxReported   = 5
)

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
	byCat := map[string]*catAgg{}
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

		cat := syscalls.Category(name)
		ca := byCat[cat]
		if ca == nil {
			ca = &catAgg{hist: make([]uint64, model.HistBuckets)}
			byCat[cat] = ca
		}
		ca.count += e.Count
		ca.totalNs += e.TotalNs
		for i, c := range e.Hist {
			ca.hist[i] += c
		}

		st := bySys[e.Syscall]
		if st == nil {
			st = &model.SyscallStat{Name: name, Nr: e.Syscall, Category: cat, Blocking: syscalls.IsBlocking(name), Hist: make([]uint64, model.HistBuckets)}
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
			delta[e.Syscall][i] += e.Hist[i] - pe.Hist[i]
		}
		dc := e.Count - pe.Count
		deltaCnt[e.Syscall] += dc
		ca.deltaCnt += dc
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

	var allNs uint64
	for _, ca := range byCat {
		allNs += ca.totalNs
	}
	for name, ca := range byCat {
		cs := model.CategoryStat{Name: name, Count: ca.count, TotalNs: ca.totalNs}
		if cs.Count > 0 {
			cs.AvgNs = float64(cs.TotalNs) / float64(cs.Count)
		}
		cs.P50Ns = model.Percentile(ca.hist, 0.50)
		cs.P95Ns = model.Percentile(ca.hist, 0.95)
		cs.P99Ns = model.Percentile(ca.hist, 0.99)
		if !first && elapsed > 0 {
			cs.Rate = float64(ca.deltaCnt) / elapsed
		}
		if allNs > 0 {
			cs.Share = float64(cs.TotalNs) / float64(allNs)
		}
		snap.Categories = append(snap.Categories, cs)
	}
	sort.Slice(snap.Categories, func(i, j int) bool { return snap.Categories[i].TotalNs > snap.Categories[j].TotalNs })

	if !first {
		snap.Anomalies = detectAnomalies(hp, s.history)
	}

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

// detectAnomalies compares the last interval against the median p95 of the
// preceding points. A syscall is flagged when its p95 is at least 2x the
// baseline and the increase is large enough to notice.
func detectAnomalies(cur model.HistoryPoint, prior []model.HistoryPoint) []model.Anomaly {
	if len(prior) < spikeMinBasePoints {
		return nil
	}
	start := len(prior) - spikeBaseWindow
	if start < 0 {
		start = 0
	}
	window := prior[start:]

	var out []model.Anomaly
	for name, lat := range cur.Syscalls {
		if lat.Count < spikeMinCount || lat.P95Ns <= 0 {
			continue
		}
		base := medianP95(window, name)
		if base <= 0 {
			continue
		}
		ratio := lat.P95Ns / base
		if ratio < spikeFactor || lat.P95Ns-base < spikeMinDeltaNs {
			continue
		}
		out = append(out, model.Anomaly{
			Name: name, Count: lat.Count, P95Ns: lat.P95Ns,
			BaseNs: base, Ratio: ratio, Time: cur.Time,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ratio > out[j].Ratio })
	if len(out) > spikeMaxReported {
		out = out[:spikeMaxReported]
	}
	return out
}

func medianP95(points []model.HistoryPoint, name string) float64 {
	vals := make([]float64, 0, len(points))
	for _, p := range points {
		if l, ok := p.Syscalls[name]; ok && l.Count > 0 && l.P95Ns > 0 {
			vals = append(vals, l.P95Ns)
		}
	}
	if len(vals) < spikeMinBasePoints {
		return 0
	}
	sort.Float64s(vals)
	return vals[len(vals)/2]
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
