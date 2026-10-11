package collector

import (
	"math"
	"math/rand"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/syscalls"
)

type fakeKey struct{ pid, nr uint32 }

type fakeProc struct {
	pid  uint32
	comm string
}

// Fake generates plausible syscall activity so the store, CLI and web UI can
// run on a Mac (or anywhere without eBPF).
type Fake struct {
	rng     *rand.Rand
	procs   []fakeProc
	profile []fakeCall
	state   map[fakeKey]*model.Entry
}

type fakeCall struct {
	name    string
	calls   int     // calls per read
	medianN float64 // median latency in ns
	spread  float64 // log-normal sigma
}

func NewFake() *Fake {
	return &Fake{
		rng: rand.New(rand.NewSource(1)),
		procs: []fakeProc{
			{1201, "nginx"}, {2330, "postgres"}, {4410, "node"}, {5120, "sysprof-demo"},
		},
		profile: []fakeCall{
			{"read", 400, 2_000, 1.0},
			{"write", 300, 4_000, 1.1},
			{"openat", 60, 12_000, 0.8},
			{"close", 60, 900, 0.5},
			{"fsync", 4, 3_000_000, 1.2},
			{"futex", 120, 80_000, 2.0},
			{"epoll_wait", 50, 1_500_000, 1.5},
			{"recvfrom", 150, 9_000, 1.3},
			{"sendto", 150, 7_000, 1.0},
		},
		state: map[fakeKey]*model.Entry{},
	}
}

func (f *Fake) Read() ([]model.Entry, error) {
	for _, p := range f.procs {
		for _, c := range f.profile {
			nr, ok := syscalls.Number(c.name)
			if !ok {
				continue
			}
			k := fakeKey{p.pid, nr}
			e := f.state[k]
			if e == nil {
				e = &model.Entry{PID: p.pid, Comm: p.comm, Syscall: nr}
				f.state[k] = e
			}
			n := c.calls/2 + f.rng.Intn(c.calls)
			for i := 0; i < n; i++ {
				ns := c.medianN * math.Exp(f.rng.NormFloat64()*c.spread)
				if ns < 1 {
					ns = 1
				}
				v := uint64(ns)
				e.Count++
				e.TotalNs += v
				if v > e.MaxNs {
					e.MaxNs = v
				}
				slot := bucket(v)
				e.Hist[slot]++
			}
		}
	}
	out := make([]model.Entry, 0, len(f.state))
	for _, e := range f.state {
		out = append(out, *e)
	}
	return out, nil
}

func (f *Fake) Close() error { return nil }

func bucket(v uint64) int {
	b := 0
	for v > 1 && b < model.HistBuckets-1 {
		v >>= 1
		b++
	}
	return b
}
