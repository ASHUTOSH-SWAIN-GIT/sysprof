//go:build linux

package shield

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Compile bpf/shield_lsm.c and generate Go bindings (make generate).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang shield ../../bpf/shield_lsm.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu -O2 -g -Wall

// Mirrors struct rule and struct event in bpf/shield_lsm.c.
type kernelRule struct {
	PID     uint32
	Active  uint8
	Kind    uint8
	Action  uint8
	PathLen uint8
	Comm    [16]byte
	Path    [64]byte
}

type kernelEvent struct {
	TS     uint64
	PID    uint32
	Rule   uint32
	Kind   uint8
	Action uint8
	Comm   [16]byte
	Path   [64]byte
	_      [2]byte // struct padding
}

var kindNames = map[uint8]string{1: KindExec, 2: KindOpen, 3: KindPtrace}
var kindCodes = map[string]uint8{KindExec: 1, KindOpen: 2, KindPtrace: 3}
var actionNames = map[uint8]string{1: ActionEPERM, 2: ActionKill}
var actionCodes = map[string]uint8{ActionEPERM: 1, ActionKill: 2}

// Kernel enforces rules with BPF LSM hooks.
type Kernel struct {
	objs   shieldObjects
	links  []link.Link
	reader *ringbuf.Reader

	mu     sync.Mutex
	slots  [MaxRules]*Rule // index is the array map key
	nextID int
	events []Event
}

func NewKernel() (Shield, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	k := &Kernel{nextID: 1}
	if err := loadShieldObjects(&k.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected shield: %+v", ve)
		}
		return nil, fmt.Errorf("load shield: %w", err)
	}

	for _, p := range []struct {
		hook string
		prog *ebpf.Program
	}{
		{"bprm_check_security", k.objs.ShieldExec},
		{"file_open", k.objs.ShieldOpen},
		{"ptrace_access_check", k.objs.ShieldPtrace},
	} {
		l, err := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if err != nil {
			k.Close()
			return nil, fmt.Errorf("attach LSM %s (is \"bpf\" in /sys/kernel/security/lsm?): %w", p.hook, err)
		}
		k.links = append(k.links, l)
	}

	var zero uint32
	if err := k.objs.Config.Put(zero, uint64(os.Getpid())); err != nil {
		k.Close()
		return nil, err
	}
	rd, err := ringbuf.NewReader(k.objs.Events)
	if err != nil {
		k.Close()
		return nil, err
	}
	k.reader = rd
	go k.readEvents()
	return k, nil
}

func (k *Kernel) readEvents() {
	for {
		rec, err := k.reader.Read()
		if err != nil {
			return // closed
		}
		var ke kernelEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ke); err != nil {
			continue
		}
		k.mu.Lock()
		name := "?"
		if int(ke.Rule) < len(k.slots) && k.slots[ke.Rule] != nil {
			name = k.slots[ke.Rule].Name
		}
		ev := Event{
			Time:   time.Now(),
			PID:    ke.PID,
			Comm:   cstr(ke.Comm[:]),
			Rule:   name,
			Kind:   kindNames[ke.Kind],
			Path:   cstr(ke.Path[:]),
			Action: actionNames[ke.Action],
		}
		k.events = append([]Event{ev}, k.events...)
		if len(k.events) > maxEvents {
			k.events = k.events[:maxEvents]
		}
		k.mu.Unlock()
	}
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func (k *Kernel) State() State {
	k.mu.Lock()
	defer k.mu.Unlock()
	st := State{Mode: ModeKernel, Rules: []Rule{}, Events: append([]Event{}, k.events...)}
	for i, r := range k.slots {
		if r == nil {
			continue
		}
		var n uint64
		k.objs.Blocked.Lookup(uint32(i), &n)
		cp := *r
		cp.Blocked = n
		st.Rules = append(st.Rules, cp)
	}
	return st
}

func (k *Kernel) AddRule(r Rule) (Rule, error) {
	if err := Validate(r); err != nil {
		return Rule{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.add(r)
}

func (k *Kernel) add(r Rule) (Rule, error) {
	slot := -1
	for i, s := range k.slots {
		if s == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		return Rule{}, fmt.Errorf("at most %d rules", MaxRules)
	}
	r.ID, r.Blocked = k.nextID, 0
	k.nextID++

	if err := k.objs.Blocked.Put(uint32(slot), uint64(0)); err != nil {
		return Rule{}, err
	}
	kr := kernelRule{
		PID: r.PID, Active: 1, Kind: kindCodes[r.Kind],
		Action: actionCodes[r.Action], PathLen: uint8(len(r.Path)),
	}
	copy(kr.Comm[:], r.Comm)
	copy(kr.Path[:], r.Path)
	if err := k.objs.Rules.Put(uint32(slot), kr); err != nil {
		return Rule{}, err
	}
	k.slots[slot] = &r
	k.syncOpenCount()
	return r, nil
}

func (k *Kernel) DeleteRule(id int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, r := range k.slots {
		if r != nil && r.ID == id {
			if err := k.objs.Rules.Put(uint32(i), kernelRule{}); err != nil {
				return err
			}
			k.slots[i] = nil
			k.syncOpenCount()
			return nil
		}
	}
	return fmt.Errorf("no rule %d", id)
}

// syncOpenCount tells the kernel whether any open rule exists, so the hot
// file_open path can skip resolving the path when nothing could match.
func (k *Kernel) syncOpenCount() {
	var n uint64
	for _, r := range k.slots {
		if r != nil && r.Kind == KindOpen {
			n++
		}
	}
	k.objs.Config.Put(uint32(1), n)
}

func (k *Kernel) Simulate(ctx context.Context) ([]Attempt, error) {
	k.mu.Lock()
	for _, d := range DemoRules() {
		found := false
		for _, r := range k.slots {
			if r != nil && r.Name == d.Name {
				found = true
			}
		}
		if !found {
			if _, err := k.add(d); err != nil {
				k.mu.Unlock()
				return nil, err
			}
		}
	}
	k.mu.Unlock()

	if err := os.MkdirAll(CanaryDir, 0o755); err != nil {
		return nil, err
	}
	for _, f := range []string{"block-me", "kill-me"} {
		if err := os.WriteFile(CanaryDir+"/"+f, []byte("canary\n"), 0o644); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, self, "__victim").Output()
	attempts := parseAttempts(out)
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return attempts, err
	}
	return attempts, nil
}

func (k *Kernel) Close() error {
	if k.reader != nil {
		k.reader.Close()
	}
	for _, l := range k.links {
		l.Close()
	}
	return k.objs.Close()
}
