// Package cli renders snapshots for the terminal.
package cli

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
)

// FormatNs prints nanoseconds with a readable unit.
func FormatNs(ns float64) string {
	switch {
	case ns < 1e3:
		return fmt.Sprintf("%.0fns", ns)
	case ns < 1e6:
		return fmt.Sprintf("%.1fus", ns/1e3)
	case ns < 1e9:
		return fmt.Sprintf("%.1fms", ns/1e6)
	default:
		return fmt.Sprintf("%.2fs", ns/1e9)
	}
}

// RenderTop writes a top-like table: syscalls first, then processes.
// Blocking syscalls are tagged "wait" so they are not mistaken for slow ones.
func RenderTop(w io.Writer, s model.Snapshot, rows int) {
	fmt.Fprintf(w, "sysprof  %s  %.0f calls/s\n", s.Time.Format(time.TimeOnly), s.Rate)
	for _, a := range s.Anomalies {
		fmt.Fprintf(w, "spike  %s  p95 %s  %.1fx baseline\n", a.Name, FormatNs(a.P95Ns), a.Ratio)
	}
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SYSCALL\tCOUNT\tCALLS/S\tTOTAL\tAVG\tP50\tP95\tP99\tMAX\t")
	for i, st := range s.Syscalls {
		if i >= rows {
			break
		}
		name := st.Name
		if st.Blocking {
			name += " (wait)"
		}
		fmt.Fprintf(tw, "%s\t%d\t%.0f\t%s\t%s\t%s\t%s\t%s\t%s\t\n", name, st.Count, st.Rate,
			FormatNs(float64(st.TotalNs)), FormatNs(st.AvgNs), FormatNs(st.P50Ns),
			FormatNs(st.P95Ns), FormatNs(st.P99Ns), FormatNs(float64(st.MaxNs)))
	}
	tw.Flush()

	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROCESS\tPID\tCOUNT\tCALLS/S\tTOTAL\tAVG\tTOP SYSCALL\t")
	for i, p := range s.Processes {
		if i >= rows/2 {
			break
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.0f\t%s\t%s\t%s\t\n", p.Comm, p.PID, p.Count, p.Rate,
			FormatNs(float64(p.TotalNs)), FormatNs(p.AvgNs), p.TopSyscall)
	}
	tw.Flush()

	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CATEGORY\tCOUNT\tCALLS/S\tTOTAL\tAVG\tP95\tSHARE\t")
	for _, c := range s.Categories {
		if c.Count == 0 {
			continue
		}
		fmt.Fprintf(tw, "%s\t%d\t%.0f\t%s\t%s\t%s\t%.0f%%\t\n", c.Name, c.Count, c.Rate,
			FormatNs(float64(c.TotalNs)), FormatNs(c.AvgNs), FormatNs(c.P95Ns), c.Share*100)
	}
	tw.Flush()
}
