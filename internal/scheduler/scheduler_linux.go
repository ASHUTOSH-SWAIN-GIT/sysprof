//go:build linux

package scheduler

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Linux implementation: batch workers are `sh` busy loops, the policy is
// their nice value, and a goroutine measures how late 1ms sleeps wake up.
type Linux struct {
	mu       sync.Mutex
	policy   string
	workers  []*worker
	stressTo time.Time

	samples []sample // raw jitter samples for the last jitterWindow
	history []float64
	stop    chan struct{}

	prevCPU  map[int]uint64
	prevTime time.Time
}

// worker is one stress process group (timeout + sh).
type worker struct {
	pid  int
	done chan struct{}
}

type sample struct {
	at time.Time
	ns float64
}

func NewKernel() (Scheduler, error) {
	l := &Linux{policy: PolicyStandard, stop: make(chan struct{}), prevCPU: map[int]uint64{}}
	go l.probe()
	go l.rollHistory()
	return l, nil
}

// probe repeatedly sleeps 1ms and records how late it wakes up. Under CPU
// contention the overshoot grows, which is the scheduling jitter users feel.
func (l *Linux) probe() {
	runtime.LockOSThread()
	for {
		select {
		case <-l.stop:
			return
		default:
		}
		t := time.Now()
		time.Sleep(time.Millisecond)
		over := time.Since(t) - time.Millisecond
		if over < 0 {
			over = 0
		}
		l.mu.Lock()
		l.samples = append(l.samples, sample{at: t, ns: float64(over.Nanoseconds())})
		cut := t.Add(-jitterWindow)
		i := 0
		for i < len(l.samples) && l.samples[i].at.Before(cut) {
			i++
		}
		l.samples = l.samples[i:]
		l.mu.Unlock()
	}
}

func (l *Linux) rollHistory() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.mu.Lock()
			raw := make([]float64, 0, len(l.samples))
			cut := time.Now().Add(-time.Second)
			for _, s := range l.samples {
				if s.at.After(cut) {
					raw = append(raw, s.ns)
				}
			}
			_, p99, _ := jitterStats(raw)
			l.history = append(l.history, p99)
			if len(l.history) > historyLen {
				l.history = l.history[1:]
			}
			l.mu.Unlock()
		}
	}
}

func (l *Linux) State() State {
	l.mu.Lock()
	defer l.mu.Unlock()

	raw := make([]float64, len(l.samples))
	for i, s := range l.samples {
		raw[i] = s.ns
	}
	avg, p99, max := jitterStats(raw)

	_, schedExt := os.Stat("/sys/kernel/sched_ext")
	st := State{
		Mode: ModeKernel, Policy: l.policy, Policies: Policies, NCPU: runtime.NumCPU(),
		Jitter:   Jitter{AvgUs: avg, P99Us: p99, MaxUs: max, History: append([]float64{}, l.history...)},
		SchedExt: schedExt == nil,
	}
	l.reap()
	st.Stress = len(l.workers)
	if st.Stress > 0 {
		st.StressEnds = l.stressTo.Unix()
	}
	st.Procs = l.procs()
	return st
}

// reap forgets workers that have exited. Callers hold l.mu.
func (l *Linux) reap() {
	alive := l.workers[:0]
	for _, w := range l.workers {
		select {
		case <-w.done:
		default:
			alive = append(alive, w)
		}
	}
	l.workers = alive
}

func (l *Linux) SetPolicy(name string) error {
	p, ok := FindPolicy(name)
	if !ok {
		return fmt.Errorf("unknown policy")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.policy = name
	for _, w := range l.workers {
		unix.Setpriority(unix.PRIO_PGRP, w.pid, p.Nice)
	}
	return nil
}

// Stress starts 2 busy workers per CPU, enough to saturate the machine.
func (l *Linux) Stress() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reap()
	if len(l.workers) > 0 {
		return fmt.Errorf("stress already running")
	}
	p, _ := FindPolicy(l.policy)
	n := 2 * runtime.NumCPU()
	if n > 16 {
		n = 16
	}
	for i := 0; i < n; i++ {
		// `timeout` bounds the load even if sysprof dies without cleanup.
		// Own process group so the nice value covers timeout and sh.
		cmd := exec.Command("timeout", strconv.Itoa(StressSeconds), "sh", "-c", "while :; do :; done")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		w := &worker{pid: cmd.Process.Pid, done: make(chan struct{})}
		go func() { cmd.Wait(); close(w.done) }()
		l.workers = append(l.workers, w)
		unix.Setpriority(unix.PRIO_PGRP, w.pid, p.Nice)
	}
	l.stressTo = time.Now().Add(StressSeconds * time.Second)
	return nil
}

func (l *Linux) Close() error {
	close(l.stop)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.workers {
		syscall.Kill(-w.pid, syscall.SIGKILL)
	}
	return nil
}

// procs returns this daemon, the stress workers and the busiest other
// processes. Callers hold l.mu.
func (l *Linux) procs() []Proc {
	now := time.Now()
	elapsed := now.Sub(l.prevTime).Seconds()
	hz := 100.0 // USER_HZ is 100 on Linux
	self := os.Getpid()
	isWorker := map[int]bool{}
	for _, w := range l.workers {
		isWorker[w.pid] = true
	}

	entries, _ := os.ReadDir("/proc")
	cur := map[int]uint64{}
	var all []Proc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		name, ticks, nice, pgrp, ok := readStat(pid)
		if !ok {
			continue
		}
		cur[pid] = ticks
		var cpu float64
		if prev, seen := l.prevCPU[pid]; seen && elapsed > 0 {
			cpu = float64(ticks-prev) / hz / elapsed * 100
		}
		tier := "Other"
		switch {
		case pid == self:
			tier, name = "Critical", "sysprof"
		case isWorker[pgrp]:
			tier, name = "Batch", "stress-worker"
		}
		all = append(all, Proc{PID: pid, Name: name, Tier: tier, Nice: nice, CPUPercent: cpu})
	}
	l.prevCPU, l.prevTime = cur, now

	sort.Slice(all, func(i, j int) bool { return all[i].CPUPercent > all[j].CPUPercent })
	var out []Proc
	others, workers := 0, 0
	for _, p := range all {
		switch {
		case p.Tier == "Critical":
		case p.Tier == "Batch":
			if workers++; workers > 4 {
				continue
			}
		default:
			if others++; others > 4 {
				continue
			}
		}
		p.Affinity = affinity(p.PID)
		p.Preemptions = preemptions(p.PID)
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tier < out[j].Tier })
	return out
}

// readStat parses /proc/<pid>/stat: comm is in parens and may contain spaces.
func readStat(pid int) (name string, ticks uint64, nice, pgrp int, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return
	}
	s := string(b)
	lp, rp := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if lp < 0 || rp < lp {
		return
	}
	name = s[lp+1 : rp]
	f := strings.Fields(s[rp+2:]) // f[0] is state (field 3)
	if len(f) < 17 {
		return
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64) // field 14 utime
	st, _ := strconv.ParseUint(f[12], 10, 64) // field 15 stime
	n, _ := strconv.Atoi(f[16])               // field 19 nice
	pg, _ := strconv.Atoi(f[2])               // field 5 pgrp
	return name, ut + st, n, pg, true
}

func affinity(pid int) string {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(pid, &set); err != nil {
		return "-"
	}
	var cpus []int
	for i := 0; i < runtime.NumCPU() || i < 64; i++ {
		if set.IsSet(i) {
			cpus = append(cpus, i)
		}
	}
	return rangeString(cpus)
}

func rangeString(c []int) string {
	if len(c) == 0 {
		return "-"
	}
	var parts []string
	start, prev := c[0], c[0]
	flush := func() {
		if start == prev {
			parts = append(parts, strconv.Itoa(start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", start, prev))
		}
	}
	for _, v := range c[1:] {
		if v == prev+1 {
			prev = v
			continue
		}
		flush()
		start, prev = v, v
	}
	flush()
	return strings.Join(parts, ",")
}

func preemptions(pid int) uint64 {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "nonvoluntary_ctxt_switches:"); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}
