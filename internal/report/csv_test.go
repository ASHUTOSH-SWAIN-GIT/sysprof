package report

import (
	"strings"
	"testing"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
)

func TestWriteSyscalls(t *testing.T) {
	s := model.Snapshot{Syscalls: []model.SyscallStat{{
		Name: "read", Nr: 63, Category: "file", Count: 2, TotalNs: 3000,
		AvgNs: 1500, P50Ns: 1000, P95Ns: 2000, P99Ns: 2000, MaxNs: 2000, Rate: 1.5,
	}}}
	var b strings.Builder
	if err := Write(&b, s, "syscalls"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines:\n%s", len(lines), b.String())
	}
	if !strings.HasPrefix(lines[0], "syscall,nr,category") {
		t.Fatalf("header = %q", lines[0])
	}
	if lines[1] != "read,63,file,false,2,1.5,3000,1500,1000,2000,2000,2000" {
		t.Fatalf("row = %q", lines[1])
	}
}

func TestWriteCategoriesAndUnknownKind(t *testing.T) {
	s := model.Snapshot{Categories: []model.CategoryStat{{Name: "file", Count: 1, TotalNs: 10, Share: 1}}}
	var b strings.Builder
	if err := Write(&b, s, "categories"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "file,1,0,10,0,0,0,0,1") {
		t.Fatalf("categories CSV = %q", b.String())
	}
	if err := Write(&b, s, "bogus"); err == nil {
		t.Fatal("unknown kind should fail")
	}
}
