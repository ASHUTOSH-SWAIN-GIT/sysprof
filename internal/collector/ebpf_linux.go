//go:build linux

package collector

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Compile the C program and generate Go bindings. Run on Linux (make generate).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang syscallLatency ../../bpf/syscall_latency.c -- -I../../bpf -O2 -g -Wall

// Mirrors struct stat_key and struct stat_val in bpf/syscall_latency.c.
type statKey struct {
	PID     uint32
	Syscall uint32
}

type statVal struct {
	Count   uint64
	TotalNs uint64
	MaxNs   uint64
	Hist    [model.HistBuckets]uint64
	Comm    [16]byte
}

// EBPF reads syscall latency from the kernel through tracepoints.
type EBPF struct {
	objs    syscallLatencyObjects
	links   []link.Link
	selfPID uint32
}

func NewEBPF() (Collector, error) {
	// Kernels before 5.11 charge map memory against RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	e := &EBPF{selfPID: uint32(os.Getpid())}
	if err := loadSyscallLatencyObjects(&e.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program: %+v", ve)
		}
		return nil, fmt.Errorf("load objects (need root or CAP_BPF+CAP_PERFMON): %w", err)
	}

	enter, err := link.Tracepoint("raw_syscalls", "sys_enter", e.objs.HandleSysEnter, nil)
	if err != nil {
		e.objs.Close()
		return nil, fmt.Errorf("attach sys_enter (is tracefs mounted?): %w", err)
	}
	exit, err := link.Tracepoint("raw_syscalls", "sys_exit", e.objs.HandleSysExit, nil)
	if err != nil {
		enter.Close()
		e.objs.Close()
		return nil, fmt.Errorf("attach sys_exit: %w", err)
	}
	e.links = []link.Link{enter, exit}
	return e, nil
}

func (e *EBPF) Read() ([]model.Entry, error) {
	var (
		out []model.Entry
		k   statKey
		v   statVal
	)
	it := e.objs.Stats.Iterate()
	for it.Next(&k, &v) {
		// Skip ourselves, otherwise reading the map shows up in the results.
		if k.PID == e.selfPID {
			continue
		}
		out = append(out, model.Entry{
			PID:     k.PID,
			Comm:    string(bytes.TrimRight(v.Comm[:], "\x00")),
			Syscall: k.Syscall,
			Count:   v.Count,
			TotalNs: v.TotalNs,
			MaxNs:   v.MaxNs,
			Hist:    v.Hist,
		})
	}
	return out, it.Err()
}

// Close detaches the programs and frees the maps.
func (e *EBPF) Close() error {
	for _, l := range e.links {
		l.Close()
	}
	return e.objs.Close()
}
