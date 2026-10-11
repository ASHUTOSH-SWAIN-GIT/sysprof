//go:build linux

package sockbypass

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Compile bpf/sock_bypass.c and generate Go bindings (make generate).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang sockBypass ../../bpf/sock_bypass.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu -O2 -g -Wall

const cgroupRoot = "/sys/fs/cgroup"

// Mirrors struct sock_key and struct conn_stat in bpf/sock_bypass.c.
type sockKey struct{ SIP, DIP, SPort, DPort uint32 }
type connStat struct{ Messages, Bytes uint64 }

// Kernel runs the sockops and sk_msg programs.
type Kernel struct {
	objs  sockBypassObjects
	links []link.Link

	mu      sync.Mutex
	enabled bool
	last    *BenchResult
	benchMu sync.Mutex // one benchmark at a time
	msgOpts *link.RawAttachProgramOptions
}

func NewKernel() (Bypass, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	k := &Kernel{}
	if err := loadSockBypassObjects(&k.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected sock bypass: %+v", ve)
		}
		return nil, fmt.Errorf("load sock bypass: %w", err)
	}

	ops, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupRoot,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: k.objs.BypassSockops,
	})
	if err != nil {
		k.objs.Close()
		return nil, fmt.Errorf("attach sockops to %s (cgroup v2 needed): %w", cgroupRoot, err)
	}
	msgOpts := link.RawAttachProgramOptions{
		Target:  k.objs.Sockhash.FD(),
		Program: k.objs.BypassMsg,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	if err := link.RawAttachProgram(msgOpts); err != nil {
		ops.Close()
		k.objs.Close()
		return nil, fmt.Errorf("attach sk_msg: %w", err)
	}
	k.links = []link.Link{ops}
	k.msgOpts = &msgOpts

	if err := k.SetEnabled(true); err != nil {
		k.Close()
		return nil, err
	}
	return k, nil
}

func (k *Kernel) SetEnabled(on bool) error {
	var v uint32
	if on {
		v = 1
	}
	if err := k.objs.Enabled.Put(uint32(0), v); err != nil {
		return err
	}
	k.mu.Lock()
	k.enabled = on
	k.mu.Unlock()
	return nil
}

func (k *Kernel) State() State {
	k.mu.Lock()
	st := State{Mode: ModeKernel, Enabled: k.enabled, Conns: []Conn{}, LastBench: k.last}
	k.mu.Unlock()

	// Each direction is its own entry. Merge them into one row per pair.
	merged := map[[2]string]*Conn{}
	var key sockKey
	var val connStat
	it := k.objs.Conns.Iterate()
	for it.Next(&key, &val) {
		a := fmt.Sprintf("%s:%d", ip(key.SIP), key.SPort)
		b := fmt.Sprintf("%s:%d", ip(key.DIP), key.DPort)
		if a > b {
			a, b = b, a
		}
		c := merged[[2]string{a, b}]
		if c == nil {
			c = &Conn{A: a, B: b, Layers: layers}
			merged[[2]string{a, b}] = c
		}
		c.Messages += val.Messages
		c.Bytes += val.Bytes
	}
	for _, c := range merged {
		st.Conns = append(st.Conns, *c)
		st.Messages += c.Messages
		st.Bytes += c.Bytes
	}
	sort.Slice(st.Conns, func(i, j int) bool { return st.Conns[i].Bytes > st.Conns[j].Bytes })
	if len(st.Conns) > 12 {
		st.Conns = st.Conns[:12]
	}
	return st
}

func ip(v uint32) net.IP {
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (k *Kernel) Benchmark(ctx context.Context, rounds int) (BenchResult, error) {
	rounds, err := validateRounds(rounds)
	if err != nil {
		return BenchResult{}, err
	}
	if !k.benchMu.TryLock() {
		return BenchResult{}, errors.New("a benchmark is already running")
	}
	defer k.benchMu.Unlock()

	k.mu.Lock()
	prev := k.enabled
	k.mu.Unlock()
	defer k.SetEnabled(prev)

	if err := k.SetEnabled(false); err != nil {
		return BenchResult{}, err
	}
	std, err := runPingPong(ctx, rounds)
	if err != nil {
		return BenchResult{}, err
	}
	if err := k.SetEnabled(true); err != nil {
		return BenchResult{}, err
	}
	byp, err := runPingPong(ctx, rounds)
	if err != nil {
		return BenchResult{}, err
	}

	res := BenchResult{Standard: std, Bypass: byp, GainPercent: gain(std, byp)}
	k.mu.Lock()
	k.last = &res
	k.mu.Unlock()
	return res, nil
}

func (k *Kernel) Close() error {
	if k.msgOpts != nil {
		link.RawDetachProgram(link.RawDetachProgramOptions{
			Target: k.msgOpts.Target, Program: k.msgOpts.Program, Attach: k.msgOpts.Attach,
		})
	}
	for _, l := range k.links {
		l.Close()
	}
	return k.objs.Close()
}
