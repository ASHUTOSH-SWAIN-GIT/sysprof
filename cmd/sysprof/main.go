// sysprof measures Linux syscall latency with eBPF.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/cli"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/collector"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/report"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/scheduler"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/server"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/shield"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/sockbypass"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/store"
	"github.com/spf13/cobra"
)

// historyWindow is how many intervals the store keeps (5 minutes at 1s).
const historyWindow = 300

type options struct {
	pid      uint32
	comm     string
	syscall  string
	interval time.Duration
	fake     bool
}

func main() {
	var o options
	root := &cobra.Command{
		Use:           "sysprof",
		Short:         "eBPF based syscall latency profiler",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.Uint32Var(&o.pid, "pid", 0, "only this process id")
	pf.StringVar(&o.comm, "comm", "", "only processes whose name contains this")
	pf.StringVar(&o.syscall, "syscall", "", "only this syscall, e.g. read")
	pf.DurationVar(&o.interval, "interval", time.Second, "how often to read the kernel maps")
	pf.BoolVar(&o.fake, "fake", false, "use generated demo data instead of eBPF (works on any OS)")

	var (
		addr        string
		allowRemote bool
		noActive    bool
	)
	serve := &cobra.Command{
		Use:   "serve",
		Short: "collect and serve the web UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(&o, func(ctx context.Context, st *store.Store) error {
				var act *server.Active
				if !noActive {
					act = newActive(o.fake)
					act.AllowRemote = allowRemote
					act.Loopback = server.IsLoopbackAddr(addr)
					defer act.Shield.Close()
					defer act.Bypass.Close()
					defer act.Sched.Close()
				}
				fmt.Fprintf(os.Stderr, "web UI on http://%s\n", addr)
				return server.Serve(ctx, addr, server.New(st, act))
			})
		},
	}
	// Loopback by default: the tool runs as root and exposes system internals.
	serve.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address")
	serve.Flags().BoolVar(&allowRemote, "unsafe-remote-control", false,
		"allow shield/bypass/scheduler changes from non-loopback requests (only behind a trusted port mapping)")
	serve.Flags().BoolVar(&noActive, "no-active", false, "profiler only, do not load the shield, bypass and scheduler programs")

	// Used by the shield attack simulation. Not for users.
	victim := &cobra.Command{
		Use:    "__victim",
		Hidden: true,
		RunE:   func(cmd *cobra.Command, args []string) error { return shield.RunVictim(os.Stdout) },
	}

	top := &cobra.Command{
		Use:   "top",
		Short: "live terminal table of syscall latency",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(&o, func(ctx context.Context, st *store.Store) error {
				updates, cancel := st.Subscribe()
				defer cancel()
				for {
					select {
					case <-ctx.Done():
						return nil
					case <-updates:
						fmt.Print("\033[H\033[2J") // clear screen
						cli.RenderTop(os.Stdout, st.Latest(), 20)
					}
				}
			})
		},
	}

	var out string
	record := &cobra.Command{
		Use:   "record",
		Short: "write one JSON snapshot per interval (JSON lines) to a file",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			return run(&o, func(ctx context.Context, st *store.Store) error {
				updates, cancel := st.Subscribe()
				defer cancel()
				fmt.Fprintf(os.Stderr, "recording to %s, Ctrl+C to stop\n", out)
				for {
					select {
					case <-ctx.Done():
						return nil
					case <-updates:
						if err := enc.Encode(st.Latest()); err != nil {
							return err
						}
					}
				}
			})
		},
	}
	record.Flags().StringVarP(&out, "output", "o", "sysprof.jsonl", "output file")

	var (
		inPath  string
		outPath string
		what    string
	)
	export := &cobra.Command{
		Use:   "export",
		Short: "convert the last snapshot of a JSONL recording to CSV",
		RunE: func(cmd *cobra.Command, args []string) error {
			snap, err := lastSnapshot(inPath)
			if err != nil {
				return err
			}
			var w io.Writer = os.Stdout
			if outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return report.Write(w, snap, what)
		},
	}
	export.Flags().StringVarP(&inPath, "input", "i", "sysprof.jsonl", "recording to read")
	export.Flags().StringVarP(&outPath, "output", "o", "-", "CSV file, - for stdout")
	export.Flags().StringVar(&what, "what", "syscalls", "syscalls, processes or categories")

	root.AddCommand(top, serve, record, export, victim)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run wires collector -> store and hands the store to the command.
// Ctrl+C cancels ctx, then the collector is closed so the kernel programs
// are detached.
func run(o *options, use func(context.Context, *store.Store) error) error {
	var (
		c   collector.Collector
		err error
	)
	if o.fake {
		c = collector.NewFake()
	} else if c, err = collector.NewEBPF(); err != nil {
		return err
	}
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st := store.New(store.Filter{PID: o.pid, Comm: o.comm, Syscall: o.syscall}, historyWindow)
	go st.Run(ctx, c, o.interval)
	return use(ctx, st)
}

// lastSnapshot reads a JSONL recording and returns the final snapshot.
func lastSnapshot(path string) (model.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.Snapshot{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var (
		last  model.Snapshot
		found bool
	)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal(line, &last); err != nil {
			return model.Snapshot{}, fmt.Errorf("%s: %w", path, err)
		}
		found = true
	}
	if err := sc.Err(); err != nil {
		return model.Snapshot{}, err
	}
	if !found {
		return model.Snapshot{}, fmt.Errorf("%s: no snapshots", path)
	}
	return last, nil
}

// newActive builds the three active subsystems. Each one degrades on its own:
// if the kernel lacks a feature that panel shows why, the rest keep working.
func newActive(fake bool) *server.Active {
	if fake {
		return &server.Active{Shield: shield.NewFake(), Bypass: sockbypass.NewFake(), Sched: scheduler.NewFake()}
	}
	a := &server.Active{}

	var err error
	if a.Shield, err = shield.NewKernel(); err != nil {
		fmt.Fprintln(os.Stderr, "shield unavailable:", err)
		a.Shield = shield.Unavailable{Reason: err.Error()}
	}
	if a.Bypass, err = sockbypass.NewKernel(); err != nil {
		fmt.Fprintln(os.Stderr, "bypass unavailable:", err)
		a.Bypass = sockbypass.Unavailable{Reason: err.Error()}
	}
	if a.Sched, err = scheduler.NewKernel(); err != nil {
		fmt.Fprintln(os.Stderr, "scheduler unavailable:", err)
		a.Sched = scheduler.Unavailable{Reason: err.Error()}
	}
	return a
}
