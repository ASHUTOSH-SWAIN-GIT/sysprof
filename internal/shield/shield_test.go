package shield

import (
	"context"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := []Rule{
		{Kind: KindExec, Action: ActionEPERM, Comm: "node", Path: "/bin/sh"},
		{Kind: KindOpen, Action: ActionKill, Path: "/etc/shadow"},
		{Kind: KindPtrace, Action: ActionEPERM},
		{Kind: KindOpen, Action: ActionEPERM, PID: 42},
	}
	for _, r := range ok {
		if err := Validate(r); err != nil {
			t.Errorf("%+v rejected: %v", r, err)
		}
	}
	bad := map[string]Rule{
		"unknown kind":      {Kind: "mount", Action: ActionEPERM, Comm: "x"},
		"unknown action":    {Kind: KindExec, Action: "DROP", Comm: "x"},
		"no target":         {Kind: KindOpen, Action: ActionEPERM},
		"blocks everything": {Kind: KindOpen, Action: ActionEPERM, Path: "/"},
		"short global path": {Kind: KindExec, Action: ActionEPERM, Path: "/bin"},
		"ptrace with path":  {Kind: KindPtrace, Action: ActionEPERM, Comm: "x", Path: "/x"},
		"long comm":         {Kind: KindExec, Action: ActionEPERM, Comm: strings.Repeat("a", 16)},
		"long path":         {Kind: KindExec, Action: ActionEPERM, Comm: "x", Path: strings.Repeat("a", 64)},
	}
	for name, r := range bad {
		if Validate(r) == nil {
			t.Errorf("%s: %+v accepted", name, r)
		}
	}
}

func TestFakeSimulateAndLimits(t *testing.T) {
	f := NewFake()
	res, err := f.Simulate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 4 || !strings.HasPrefix(res[3].Outcome, "KILLED") {
		t.Fatalf("unexpected attempts: %+v", res)
	}
	st := f.State()
	if len(st.Rules) != 4 || st.Rules[0].Blocked != 1 || len(st.Events) != 4 {
		t.Fatalf("unexpected state: %+v", st)
	}
	// running again must not duplicate the demo rules
	f.Simulate(context.Background())
	if n := len(f.State().Rules); n != 4 {
		t.Fatalf("demo rules duplicated: %d", n)
	}
	for i := 0; i < MaxRules; i++ {
		f.AddRule(Rule{Name: "x", Kind: KindExec, Action: ActionEPERM, Comm: "x"})
	}
	if _, err := f.AddRule(Rule{Kind: KindExec, Action: ActionEPERM, Comm: "x"}); err == nil {
		t.Fatal("rule limit not enforced")
	}
}
