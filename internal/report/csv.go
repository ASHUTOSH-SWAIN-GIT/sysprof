// Package report renders a snapshot as CSV for spreadsheets and coursework
// write-ups.
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
)

// Kinds lists the tables that can be exported.
var Kinds = []string{"syscalls", "processes", "categories"}

// Write renders one table of the snapshot as CSV.
func Write(w io.Writer, s model.Snapshot, kind string) error {
	cw := csv.NewWriter(w)
	switch kind {
	case "syscalls":
		cw.Write([]string{"syscall", "nr", "category", "blocking", "count", "calls_per_sec",
			"total_ns", "avg_ns", "p50_ns", "p95_ns", "p99_ns", "max_ns"})
		for _, st := range s.Syscalls {
			cw.Write([]string{st.Name, u64(uint64(st.Nr)), st.Category, strconv.FormatBool(st.Blocking),
				u64(st.Count), f(st.Rate), u64(st.TotalNs), f(st.AvgNs),
				f(st.P50Ns), f(st.P95Ns), f(st.P99Ns), u64(st.MaxNs)})
		}
	case "processes":
		cw.Write([]string{"process", "pid", "count", "calls_per_sec", "total_ns", "avg_ns", "top_syscall"})
		for _, p := range s.Processes {
			cw.Write([]string{p.Comm, u64(uint64(p.PID)), u64(p.Count), f(p.Rate),
				u64(p.TotalNs), f(p.AvgNs), p.TopSyscall})
		}
	case "categories":
		cw.Write([]string{"category", "count", "calls_per_sec", "total_ns", "avg_ns",
			"p50_ns", "p95_ns", "p99_ns", "share"})
		for _, c := range s.Categories {
			cw.Write([]string{c.Name, u64(c.Count), f(c.Rate), u64(c.TotalNs), f(c.AvgNs),
				f(c.P50Ns), f(c.P95Ns), f(c.P99Ns), f(c.Share)})
		}
	default:
		return fmt.Errorf("unknown export %q (want syscalls, processes or categories)", kind)
	}
	cw.Flush()
	return cw.Error()
}

func u64(v uint64) string { return strconv.FormatUint(v, 10) }

func f(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
