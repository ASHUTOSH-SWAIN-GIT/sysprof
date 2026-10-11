// Package shield enforces syscall policies inside the kernel (BPF LSM) and
// exposes them to the dashboard. A fake implementation lets the UI run on
// machines without BPF LSM.
package shield

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	KindExec   = "exec"
	KindOpen   = "open"
	KindPtrace = "ptrace"

	ActionEPERM = "EPERM"
	ActionKill  = "KILL"

	MaxRules   = 16
	MaxPathLen = 63 // kernel buffer is 64 bytes including the terminator
	maxEvents  = 30

	// CanaryDir holds the harmless files used by the attack simulation.
	CanaryDir = "/tmp/sysprof-canary"
	// VictimComm is the process name the demo rules target.
	VictimComm = "sysprof-victim"
)

// Rule denies an operation for matching processes.
type Rule struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Comm    string `json:"comm"` // empty = any process name
	PID     uint32 `json:"pid"`  // 0 = any process
	Kind    string `json:"kind"` // exec, open, ptrace
	Path    string `json:"path"` // path prefix, empty = any
	Action  string `json:"action"`
	Blocked uint64 `json:"blocked"`
}

// Event is one interception.
type Event struct {
	Time   time.Time `json:"time"`
	PID    uint32    `json:"pid"`
	Comm   string    `json:"comm"`
	Rule   string    `json:"rule"`
	Kind   string    `json:"kind"`
	Path   string    `json:"path"`
	Action string    `json:"action"`
}

// Mode says where enforcement happens.
const (
	ModeKernel      = "kernel"
	ModeSimulated   = "simulated"
	ModeUnavailable = "unavailable"
)

// State is what the dashboard shows.
type State struct {
	Mode   string  `json:"mode"`
	Reason string  `json:"reason,omitempty"`
	Rules  []Rule  `json:"rules"`
	Events []Event `json:"events"`
}

// Attempt is one operation the simulated attacker tried.
type Attempt struct {
	Action  string `json:"action"`
	Outcome string `json:"outcome"` // BLOCKED (EPERM), KILLED, ALLOWED
}

// Shield manages policies.
type Shield interface {
	State() State
	AddRule(Rule) (Rule, error)
	DeleteRule(id int) error
	// Simulate installs the demo rules if missing, then runs a harmless
	// attacker process that tries forbidden operations.
	Simulate(ctx context.Context) ([]Attempt, error)
	Close() error
}

// Validate rejects rules that are malformed or would lock the machine up.
func Validate(r Rule) error {
	switch r.Kind {
	case KindExec, KindOpen, KindPtrace:
	default:
		return fmt.Errorf("kind must be exec, open or ptrace")
	}
	switch r.Action {
	case ActionEPERM, ActionKill:
	default:
		return fmt.Errorf("action must be EPERM or KILL")
	}
	if len(r.Comm) > 15 {
		return fmt.Errorf("process name is limited to 15 characters")
	}
	if len(r.Path) > MaxPathLen {
		return fmt.Errorf("path is limited to %d characters", MaxPathLen)
	}
	if r.Kind == KindPtrace && r.Path != "" {
		return fmt.Errorf("ptrace rules cannot have a path")
	}
	if r.Kind != KindPtrace && r.Path == "" && r.Comm == "" && r.PID == 0 {
		return fmt.Errorf("rule needs a process name, pid or path")
	}
	// A rule with no process target applies to every process, including
	// system services. Require a specific path so it cannot block everything.
	if r.Comm == "" && r.PID == 0 && r.Kind != KindPtrace && len(r.Path) < 5 {
		return fmt.Errorf("a rule for all processes needs a specific path (at least 5 characters)")
	}
	return nil
}

// DemoRules are installed by the attack simulation.
func DemoRules() []Rule {
	return []Rule{
		{Name: "Zero-Shell", Comm: VictimComm, Kind: KindExec, Path: "/bin/sh", Action: ActionEPERM},
		{Name: "Protect Canary", Comm: VictimComm, Kind: KindOpen, Path: CanaryDir + "/block-me", Action: ActionEPERM},
		{Name: "Kill On Touch", Comm: VictimComm, Kind: KindOpen, Path: CanaryDir + "/kill-me", Action: ActionKill},
		{Name: "Anti-Debugging", Comm: VictimComm, Kind: KindPtrace, Action: ActionEPERM},
	}
}

// Unavailable is returned when the kernel cannot enforce policies.
type Unavailable struct{ Reason string }

func (u Unavailable) State() State {
	return State{Mode: ModeUnavailable, Reason: u.Reason, Rules: []Rule{}, Events: []Event{}}
}
func (u Unavailable) AddRule(Rule) (Rule, error) { return Rule{}, errors.New(u.Reason) }
func (u Unavailable) DeleteRule(int) error       { return errors.New(u.Reason) }
func (u Unavailable) Simulate(context.Context) ([]Attempt, error) {
	return nil, errors.New(u.Reason)
}
func (u Unavailable) Close() error { return nil }

// Fake keeps rules in memory and fabricates interceptions.
type Fake struct {
	mu     sync.Mutex
	nextID int
	rules  []Rule
	events []Event
}

func NewFake() *Fake { return &Fake{nextID: 1} }

func (f *Fake) State() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return State{
		Mode:   ModeSimulated,
		Rules:  append([]Rule{}, f.rules...),
		Events: append([]Event{}, f.events...),
	}
}

func (f *Fake) AddRule(r Rule) (Rule, error) {
	if err := Validate(r); err != nil {
		return Rule{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.add(r)
}

func (f *Fake) add(r Rule) (Rule, error) {
	if len(f.rules) >= MaxRules {
		return Rule{}, fmt.Errorf("at most %d rules", MaxRules)
	}
	r.ID, r.Blocked = f.nextID, 0
	f.nextID++
	f.rules = append(f.rules, r)
	return r, nil
}

func (f *Fake) DeleteRule(id int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.rules {
		if r.ID == id {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no rule %d", id)
}

func (f *Fake) Simulate(ctx context.Context) ([]Attempt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range DemoRules() {
		found := false
		for _, r := range f.rules {
			if r.Name == d.Name {
				found = true
			}
		}
		if !found {
			f.add(d)
		}
	}
	steps := []struct {
		name, action, kind, path string
	}{
		{"Zero-Shell", "execve /bin/sh", KindExec, "/bin/sh"},
		{"Protect Canary", "open " + CanaryDir + "/block-me", KindOpen, CanaryDir + "/block-me"},
		{"Anti-Debugging", "ptrace attach", KindPtrace, ""},
		{"Kill On Touch", "open " + CanaryDir + "/kill-me", KindOpen, CanaryDir + "/kill-me"},
	}
	var out []Attempt
	for _, s := range steps {
		outcome := "ALLOWED"
		for i := range f.rules {
			r := &f.rules[i]
			if r.Name != s.name {
				continue
			}
			r.Blocked++
			outcome = "BLOCKED (EPERM)"
			if r.Action == ActionKill {
				outcome = "KILLED (SIGKILL)"
			}
			f.events = append([]Event{{
				Time: time.Now(), PID: 4242, Comm: VictimComm, Rule: r.Name,
				Kind: s.kind, Path: s.path, Action: r.Action,
			}}, f.events...)
			if len(f.events) > maxEvents {
				f.events = f.events[:maxEvents]
			}
			break
		}
		out = append(out, Attempt{Action: s.action, Outcome: outcome})
		if strings.HasPrefix(outcome, "KILLED") {
			break
		}
	}
	return out, nil
}

func (f *Fake) Close() error { return nil }
