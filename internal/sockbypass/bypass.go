// Package sockbypass accelerates loopback TCP with sockmap and sk_msg: data
// sent between two local sockets is moved straight into the peer's receive
// queue, skipping the TCP/IP stack. A fake implementation lets the UI run
// without the kernel feature.
package sockbypass

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	ModeKernel      = "kernel"
	ModeSimulated   = "simulated"
	ModeUnavailable = "unavailable"

	DefaultBenchRounds = 100_000
	MaxBenchRounds     = 200_000
	benchMsgSize       = 64
)

// Conn is one accelerated connection (both directions merged).
type Conn struct {
	A        string `json:"a"`
	B        string `json:"b"`
	Messages uint64 `json:"messages"`
	Bytes    uint64 `json:"bytes"`
	Layers   string `json:"layers"`
}

// Dist summarises one benchmark run.
type Dist struct {
	Rounds int      `json:"rounds"`
	MeanNs float64  `json:"mean_ns"`
	P50Ns  float64  `json:"p50_ns"`
	P95Ns  float64  `json:"p95_ns"`
	P99Ns  float64  `json:"p99_ns"`
	OpsSec float64  `json:"ops_per_sec"`
	Hist   []uint64 `json:"hist"` // log2 buckets in ns
}

// BenchResult compares the normal stack with the bypass.
type BenchResult struct {
	Standard    Dist    `json:"standard"`
	Bypass      Dist    `json:"bypass"`
	GainPercent float64 `json:"gain_percent"` // reduction in mean round trip
	Simulated   bool    `json:"simulated"`
}

// State is what the dashboard shows.
type State struct {
	Mode      string       `json:"mode"`
	Reason    string       `json:"reason,omitempty"`
	Enabled   bool         `json:"enabled"`
	Conns     []Conn       `json:"conns"`
	Messages  uint64       `json:"messages"`
	Bytes     uint64       `json:"bytes"`
	LastBench *BenchResult `json:"last_bench,omitempty"`
}

// Bypass controls the accelerator.
type Bypass interface {
	State() State
	SetEnabled(on bool) error
	// Benchmark runs a TCP ping-pong with the bypass off, then on.
	Benchmark(ctx context.Context, rounds int) (BenchResult, error)
	Close() error
}

const layers = "netfilter, IP, TCP tx, loopback"

// Unavailable is returned when the kernel cannot run the accelerator.
type Unavailable struct{ Reason string }

func (u Unavailable) State() State {
	return State{Mode: ModeUnavailable, Reason: u.Reason, Conns: []Conn{}}
}
func (u Unavailable) SetEnabled(bool) error { return errors.New(u.Reason) }
func (u Unavailable) Benchmark(context.Context, int) (BenchResult, error) {
	return BenchResult{}, errors.New(u.Reason)
}
func (u Unavailable) Close() error { return nil }

// runPingPong measures n request/response round trips of a small message over
// a fresh loopback TCP connection. A new connection per run matters: sockets
// join the bypass when they are established.
func runPingPong(ctx context.Context, n int) (Dist, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Dist{}, err
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		buf := make([]byte, benchMsgSize)
		for i := 0; i < n; i++ {
			if _, err := readFull(c, buf); err != nil {
				done <- err
				return
			}
			if _, err := c.Write(buf); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return Dist{}, err
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	msg := make([]byte, benchMsgSize)
	buf := make([]byte, benchMsgSize)
	lat := make([]int64, 0, n)
	start := time.Now()
	for i := 0; i < n; i++ {
		if i%1024 == 0 && ctx.Err() != nil {
			return Dist{}, ctx.Err()
		}
		t := time.Now()
		if _, err := c.Write(msg); err != nil {
			return Dist{}, err
		}
		if _, err := readFull(c, buf); err != nil {
			return Dist{}, err
		}
		lat = append(lat, time.Since(t).Nanoseconds())
	}
	total := time.Since(start)
	c.Close()
	if err := <-done; err != nil {
		return Dist{}, err
	}
	return summarize(lat, total), nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func summarize(lat []int64, total time.Duration) Dist {
	d := Dist{Rounds: len(lat), Hist: make([]uint64, 32)}
	if len(lat) == 0 {
		return d
	}
	var sum float64
	for _, v := range lat {
		sum += float64(v)
		b := 0
		for x := v; x > 1 && b < 31; x >>= 1 {
			b++
		}
		d.Hist[b]++
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	q := func(p float64) float64 { return float64(lat[int(p*float64(len(lat)-1))]) }
	d.MeanNs = sum / float64(len(lat))
	d.P50Ns, d.P95Ns, d.P99Ns = q(0.50), q(0.95), q(0.99)
	d.OpsSec = float64(len(lat)) / total.Seconds()
	return d
}

func gain(std, byp Dist) float64 {
	if std.MeanNs == 0 {
		return 0
	}
	return (std.MeanNs - byp.MeanNs) / std.MeanNs * 100
}

// Fake fabricates traffic and benchmark results.
type Fake struct {
	mu      sync.Mutex
	enabled bool
	last    *BenchResult
	conns   []*Conn
	rng     *rand.Rand
	tick    time.Time
}

func NewFake() *Fake {
	return &Fake{
		enabled: true,
		rng:     rand.New(rand.NewSource(7)),
		conns: []*Conn{
			{A: "127.0.0.1:8080", B: "127.0.0.1:45212", Layers: layers},
			{A: "127.0.0.1:6379", B: "127.0.0.1:51004", Layers: layers},
		},
	}
}

func (f *Fake) State() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.enabled && !f.tick.IsZero() {
		for _, c := range f.conns {
			m := uint64(f.rng.Intn(4000) + 1000)
			c.Messages += m
			c.Bytes += m * uint64(200+f.rng.Intn(300))
		}
	}
	f.tick = now
	st := State{Mode: ModeSimulated, Enabled: f.enabled, Conns: []Conn{}, LastBench: f.last}
	for _, c := range f.conns {
		st.Conns = append(st.Conns, *c)
		st.Messages += c.Messages
		st.Bytes += c.Bytes
	}
	return st
}

func (f *Fake) SetEnabled(on bool) error {
	f.mu.Lock()
	f.enabled = on
	f.mu.Unlock()
	return nil
}

func (f *Fake) Benchmark(ctx context.Context, rounds int) (BenchResult, error) {
	if rounds <= 0 {
		rounds = DefaultBenchRounds
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	synth := func(median float64) Dist {
		lat := make([]int64, rounds)
		for i := range lat {
			lat[i] = int64(median * math.Exp(f.rng.NormFloat64()*0.35))
		}
		return summarize(lat, time.Duration(float64(rounds)*median))
	}
	res := BenchResult{Standard: synth(41_000), Bypass: synth(17_000), Simulated: true}
	res.GainPercent = gain(res.Standard, res.Bypass)
	f.last = &res
	return res, nil
}

func (f *Fake) Close() error { return nil }

func validateRounds(n int) (int, error) {
	if n <= 0 {
		return DefaultBenchRounds, nil
	}
	if n > MaxBenchRounds {
		return 0, fmt.Errorf("rounds is limited to %d", MaxBenchRounds)
	}
	return n, nil
}

// ValidateRounds normalises and bounds the requested round count.
func ValidateRounds(n int) (int, error) { return validateRounds(n) }
