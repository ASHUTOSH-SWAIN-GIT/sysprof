// sysprof measures Linux syscall latency with eBPF.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/cli"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/collector"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/server"
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

	var addr string
	serve := &cobra.Command{
		Use:   "serve",
		Short: "collect and serve the web UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(&o, func(ctx context.Context, st *store.Store) error {
				fmt.Fprintf(os.Stderr, "web UI on http://%s\n", addr)
				return server.Serve(ctx, addr, server.New(st))
			})
		},
	}
	// Loopback by default: the tool runs as root and exposes system internals.
	serve.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address")

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

	root.AddCommand(top, serve, record)
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
