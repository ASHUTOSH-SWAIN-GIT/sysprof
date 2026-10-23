// Package model holds the types shared by the collector, store, CLI and API.
package model

import (
	"math"
	"time"
)

// HistBuckets is the number of log2 latency buckets. Bucket i covers
// [2^i, 2^(i+1)) nanoseconds.
const HistBuckets = 32

// Entry is the cumulative state of one (process, syscall) pair, as read
// from the kernel map.
type Entry struct {
	PID     uint32
	Comm    string
	Syscall uint32
	Count   uint64
	TotalNs uint64
	MaxNs   uint64
	Hist    [HistBuckets]uint64
}

// SyscallStat is the aggregate of one syscall across all (filtered) processes.
type SyscallStat struct {
	Name     string   `json:"name"`
	Nr       uint32   `json:"nr"`
	Category string   `json:"category"`
	Blocking bool     `json:"blocking"`
	Count    uint64   `json:"count"`
	TotalNs  uint64   `json:"total_ns"`
	AvgNs    float64  `json:"avg_ns"`
	MaxNs    uint64   `json:"max_ns"`
	P50Ns    float64  `json:"p50_ns"`
	P95Ns    float64  `json:"p95_ns"`
	P99Ns    float64  `json:"p99_ns"`
	Rate     float64  `json:"rate"` // calls per second over the last interval
	Hist     []uint64 `json:"hist"`
}

// ProcessStat is the aggregate of one process across all its syscalls.
type ProcessStat struct {
	PID        uint32  `json:"pid"`
	Comm       string  `json:"comm"`
	Count      uint64  `json:"count"`
	TotalNs    uint64  `json:"total_ns"`
	AvgNs      float64 `json:"avg_ns"`
	Rate       float64 `json:"rate"`
	TopSyscall string  `json:"top_syscall"` // by total time, blocking ones excluded
}

// CategoryStat is the aggregate of one syscall category.
type CategoryStat struct {
	Name    string  `json:"name"`
	Count   uint64  `json:"count"`
	TotalNs uint64  `json:"total_ns"`
	AvgNs   float64 `json:"avg_ns"`
	P50Ns   float64 `json:"p50_ns"`
	P95Ns   float64 `json:"p95_ns"`
	P99Ns   float64 `json:"p99_ns"`
	Rate    float64 `json:"rate"`
	Share   float64 `json:"share"` // fraction of total syscall time, 0..1
}

// Anomaly is a syscall whose latency in the last interval was well above its
// recent baseline.
type Anomaly struct {
	Name   string    `json:"name"`
	Count  uint64    `json:"count"`
	P95Ns  float64   `json:"p95_ns"`
	BaseNs float64   `json:"baseline_ns"`
	Ratio  float64   `json:"ratio"`
	Time   time.Time `json:"time"`
}

// Snapshot is the state at one point in time (cumulative since start).
type Snapshot struct {
	Time       time.Time      `json:"time"`
	Rate       float64        `json:"rate"` // total calls per second over the last interval
	Syscalls   []SyscallStat  `json:"syscalls"`
	Processes  []ProcessStat  `json:"processes"`
	Categories []CategoryStat `json:"categories"`
	Anomalies  []Anomaly      `json:"anomalies"`
}

// Latency is the per interval latency summary of one syscall.
type Latency struct {
	Count uint64  `json:"count"`
	P50Ns float64 `json:"p50_ns"`
	P95Ns float64 `json:"p95_ns"`
	P99Ns float64 `json:"p99_ns"`
}

// HistoryPoint is one interval in the rolling history.
type HistoryPoint struct {
	Time     time.Time          `json:"time"`
	Rate     float64            `json:"rate"`
	Syscalls map[string]Latency `json:"syscalls"`
}

// Percentile estimates the q-th quantile (0..1) in nanoseconds from log2
// buckets. It assumes samples are spread evenly inside a bucket, so the
// result is an approximation, not an exact value.
func Percentile(hist []uint64, q float64) float64 {
	var total uint64
	for _, c := range hist {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var seen float64
	for i, c := range hist {
		if c == 0 {
			continue
		}
		if seen+float64(c) >= target {
			lo := math.Exp2(float64(i))
			hi := math.Exp2(float64(i + 1))
			return lo + (hi-lo)*(target-seen)/float64(c)
		}
		seen += float64(c)
	}
	return math.Exp2(float64(len(hist)))
}
