// Package scheduler shows how CPU contention hurts latency-sensitive work and
// lets the dashboard change the priority policy of the stress workers.
//
// It does not load a sched_ext scheduler: that needs a kernel built with
// CONFIG_SCHED_CLASS_EXT. The policy is applied with nice values, and the
// effect is measured with a wake-up jitter probe.
package scheduler

import (
	"errors"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

const (
	ModeKernel      = "kernel"
	ModeSimulated   = "simulated"
	ModeUnavailable = "unavailable"

	PolicyStandard    = "standard"
	PolicyLatency     = "latency-first"
	PolicyInteractive = "interactive"

	StressSeconds = 20
	jitterWindow  = 5 * time.Second
	historyLen    = 60
)

// Policies lists the supported policies with their effect on stress workers.
var Policies = []Policy{
	{Name: PolicyStandard, Label: "Standard Fair", Nice: 0},
	{Name: PolicyLatency, Label: "Low-Latency First", Nice: 10},
	{Name: PolicyInteractive, Label: "Interactive Priority", Nice: 19},
}

// Policy maps a name to the nice value given to batch workers.
type Policy struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Nice  int    `json:"nice"`
}

// Proc is one row of the process table.
type Proc struct {
	PID         int     `json:"pid"`
	Name        string  `json:"name"`
	Tier        string  `json:"tier"` // Critical, Batch, Other
	Nice        int     `json:"nice"`
	CPUPercent  float64 `json:"cpu_percent"`
	Affinity    string  `json:"affinity"`
	Preemptions uint64  `json:"preemptions"` // involuntary context switches
}

// Jitter is the wake-up overshoot of a 1ms sleep, in microseconds.
type Jitter struct {
	AvgUs   float64   `json:"avg_us"`
	P99Us   float64   `json:"p99_us"`
	MaxUs   float64   `json:"max_us"`
	History []float64 `json:"history"` // p99 per second, oldest first
}

// State is what the dashboard shows.
type State struct {
	Mode       string   `json:"mode"`
	Reason     string   `json:"reason,omitempty"`
	Policy     string   `json:"policy"`
	Policies   []Policy `json:"policies"`
	NCPU       int      `json:"ncpu"`
	Stress     int      `json:"stress_workers"`
	StressEnds int64    `json:"stress_ends_unix"` // 0 when idle
	Jitter     Jitter   `json:"jitter"`
	Procs      []Proc   `json:"procs"`
	SchedExt   bool     `json:"sched_ext_available"`
}

// Scheduler controls policy and load.
type Scheduler interface {
	State() State
	SetPolicy(name string) error
	// Stress starts CPU burning workers for StressSeconds.
	Stress() error
	Close() error
}

// FindPolicy returns the policy with the given name.
func FindPolicy(name string) (Policy, bool) {
	for _, p := range Policies {
		if p.Name == name {
			return p, true
		}
	}
	return Policy{}, false
}

// Unavailable is returned when the scheduler pillar cannot run.
type Unavailable struct{ Reason string }

func (u Unavailable) State() State {
	return State{Mode: ModeUnavailable, Reason: u.Reason, Policies: Policies, Procs: []Proc{}}
}
func (u Unavailable) SetPolicy(string) error { return errors.New(u.Reason) }
func (u Unavailable) Stress() error          { return errors.New(u.Reason) }
func (u Unavailable) Close() error           { return nil }

// jitterWindowStats turns raw overshoot samples (ns) into a Jitter.
func jitterStats(samples []float64) (avg, p99, max float64) {
	if len(samples) == 0 {
		return
	}
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	var sum float64
	for _, v := range s {
		sum += v
	}
	return sum / float64(len(s)) / 1e3, s[int(0.99*float64(len(s)-1))] / 1e3, s[len(s)-1] / 1e3
}

// Fake fabricates a believable contention story.
type Fake struct {
	mu      sync.Mutex
	policy  string
	until   time.Time
	rng     *rand.Rand
	history []float64
	last    time.Time
}

func NewFake() *Fake {
	return &Fake{policy: PolicyStandard, rng: rand.New(rand.NewSource(3))}
}

func (f *Fake) State() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	stress := now.Before(f.until)

	// p99 jitter in microseconds for the current situation
	var p99 float64
	switch {
	case !stress:
		p99 = 120
	case f.policy == PolicyStandard:
		p99 = 18000
	case f.policy == PolicyLatency:
		p99 = 2500
	default:
		p99 = 450
	}
	p99 *= 0.8 + 0.4*f.rng.Float64()
	if f.last.IsZero() || now.Sub(f.last) >= time.Second {
		f.history = append(f.history, p99)
		if len(f.history) > historyLen {
			f.history = f.history[1:]
		}
		f.last = now
	}

	st := State{
		Mode: ModeSimulated, Policy: f.policy, Policies: Policies, NCPU: 4,
		Jitter: Jitter{AvgUs: p99 / 6, P99Us: p99, MaxUs: p99 * 1.6, History: append([]float64{}, f.history...)},
		Procs: []Proc{
			{PID: 4109, Name: "sysprof-api", Tier: "Critical", Nice: 0, CPUPercent: 3, Affinity: "0-3", Preemptions: 12},
		},
	}
	if stress {
		st.Stress = 8
		st.StressEnds = f.until.Unix()
		nice := 0
		if p, ok := FindPolicy(f.policy); ok {
			nice = p.Nice
		}
		for i := 0; i < 3; i++ {
			st.Procs = append(st.Procs, Proc{
				PID: 8800 + i, Name: "stress-worker", Tier: "Batch", Nice: nice,
				CPUPercent: math.Max(5, 95-float64(nice)*3), Affinity: "0-3",
				Preemptions: uint64(1400 + 90*i),
			})
		}
	}
	st.Procs = append(st.Procs, Proc{PID: 1204, Name: "background-sync", Tier: "Other", CPUPercent: 2, Affinity: "0-3", Preemptions: 310})
	return st
}

func (f *Fake) SetPolicy(name string) error {
	if _, ok := FindPolicy(name); !ok {
		return errors.New("unknown policy")
	}
	f.mu.Lock()
	f.policy = name
	f.mu.Unlock()
	return nil
}

func (f *Fake) Stress() error {
	f.mu.Lock()
	f.until = time.Now().Add(StressSeconds * time.Second)
	f.mu.Unlock()
	return nil
}

func (f *Fake) Close() error { return nil }
