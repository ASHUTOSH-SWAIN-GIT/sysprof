# sysprof: project explained

## 1. What it is

- A tool that measures how long Linux system calls take.
- It shows which syscalls are slow, which processes make them, and how
  latency is distributed.
- Built for an OS course. Delivered as one Go binary with a terminal view and a
  web UI.

## 2. Key concepts

- **System call (syscall):** how a program asks the kernel to do work (`read`,
  `write`, `openat`, `futex`, ...).
- **Syscall latency:** time between entering the kernel (`sys_enter`) and
  returning to user space (`sys_exit`).
- **eBPF:** small sandboxed programs loaded into the running kernel and
  attached to hook points. The kernel verifier checks them for safety first.
- **Tracepoint:** a stable kernel hook point. This project uses
  `raw_syscalls:sys_enter` and `raw_syscalls:sys_exit`.
- **eBPF map:** kernel memory shared between the eBPF program and user space.
- **Why not strace:** strace uses ptrace and can slow a program 10x to 100x,
  which distorts the latency being measured. eBPF overhead is very low.

## 3. How a measurement happens

1. A thread enters any syscall. The `sys_enter` program stores the current
   timestamp in the `start` map, keyed by thread id.
2. The syscall returns. The `sys_exit` program finds that timestamp and
   computes `latency = now - start`.
3. The latency is added to the `stats` map entry for `(pid, syscall)`:
   count, total time, max, and a 32 slot log2 histogram.
4. Every second the Go program reads `stats`, diffs it against the previous
   reading, and publishes a snapshot.
5. The CLI and the browser read the same snapshot.

The store adds two summaries on top of the raw counters:

- **Categories.** Each syscall name maps to a group (file, memory, network,
  process, sync, signal, time, other). Categories are aggregated like syscalls,
  and `share` says how much of the total syscall time each one used.
- **Spikes.** The current interval's p95 for a syscall is compared with the
  median p95 of up to the previous 30 intervals. If it is at least 2x the
  baseline and 25us higher (with at least 10 calls), the syscall is reported as
  an anomaly. This needs five intervals of history before it starts.

Design choices behind this:

- **Aggregate in the kernel.** Millions of syscalls per second cannot be sent
  to user space one by one. Only small summaries cross the boundary.
- **Key by thread id.** Many threads of one process can be inside syscalls at
  once. A per process key would overwrite entries.
- **Log2 histogram.** Slot `i` holds latencies in `[2^i, 2^(i+1))` ns. It is
  fixed size, cheap to update, and covers 1ns to seconds.
- **Percentiles are estimates.** p50/p95/p99 are interpolated inside a bucket,
  so they are accurate to within one power of two.
- **Blocking syscalls are tagged `wait`.** `futex`, `epoll_wait`, `nanosleep`
  wait by design, so long latency does not mean slowness.

## 4. Architecture

```
bpf/syscall_latency.c   eBPF program (C, runs in kernel)
        |
   eBPF maps (start, stats)
        |
internal/collector      loads program, reads maps every ~1s
        |
internal/store          snapshots, interval diffs, percentiles, history
        |
   +----+-----------------+
   |                      |
internal/cli        internal/server (REST + SSE)
(top, record)               |
                         web/index.html
```

- The collector sits behind an interface. A fake collector generates demo
  data, so everything above it runs on a Mac with no Linux.
- Both outputs read the same store, so the terminal and browser always agree.

## 5. Language split

- **C:** only `bpf/syscall_latency.c` (about 100 lines). The kernel side must
  be restricted C, compiled by clang to eBPF bytecode.
- **Go:** everything in user space: loader, store, HTTP server, CLI.
- **JS/HTML:** one file, `web/index.html`. It only draws what the server
  sends, no aggregation in the browser.
- The compiled eBPF object and the HTML are embedded in the binary with
  `go:embed`, so there is nothing else to install.

## 6. Repository map

| Path | What it does |
| --- | --- |
| `bpf/syscall_latency.c` | enter/exit tracepoint programs, maps, histogram |
| `bpf/shield_lsm.c` | LSM hooks that deny exec, open, ptrace by rule |
| `bpf/sock_bypass.c` | sockops + sk_msg loopback bypass |
| `bpf/headers/` | vendored eBPF helper headers (from cilium/ebpf examples) |
| `internal/collector/ebpf_linux.go` | loads and attaches the program, reads `stats` (Linux only) |
| `internal/collector/fake.go` | generated demo data for any OS |
| `internal/collector/syscalllatency_bpfel.*` | generated Go bindings and compiled object (committed) |
| `internal/model/` | shared types and percentile estimation |
| `internal/store/` | filters, interval diffs, per syscall/process/category stats, spikes, history, subscribers |
| `internal/report/` | CSV output for syscalls, processes and categories |
| `internal/server/` | profiler API, `/stream` (SSE), active control routes, request guard, static UI |
| `internal/shield/` | BPF LSM policy manager, attack simulation, fake |
| `internal/sockbypass/` | sockmap manager, benchmark, fake |
| `internal/scheduler/` | stress workers, nice policy, jitter probe, fake |
| `internal/cli/` | terminal table rendering |
| `internal/syscalls/` | syscall number to name tables (amd64, arm64) and blocking list |
| `tools/gensyscalls/` | generates those tables from the kernel's own tables |
| `cmd/sysprof/` | cobra commands: `top`, `serve`, `record` |
| `web/` | embedded single page UI |
| `scripts/demo-docker.sh` | real data demo inside Docker's Linux VM |

## 7. Where things happen, step by step

- **Startup** (`cmd/sysprof/main.go`): picks the fake or eBPF collector,
  creates the store, starts the read loop, then runs the chosen command.
- **Attach** (`ebpf_linux.go`): raises the memlock limit, loads the object,
  attaches both tracepoints. Errors mention root and tracefs because those
  are the usual causes.
- **Read loop** (`store.Run`): every interval, read entries, call `Update`.
- **Update** (`store.Update`): apply filters, aggregate by syscall and by
  process, diff against the previous reading for rates and interval
  percentiles. If a counter went down (pid reused), the entry is treated as
  new.
- **Streaming** (`server.stream`): each store update signals subscribers, and
  every connected browser gets `{snapshot, history}` as one SSE event.
- **Shutdown:** Ctrl+C cancels the context and closes the links. If the
  process crashes, the kernel removes the programs automatically.

## 8. Commands

- `sysprof top`: live terminal table, like `top` for syscalls.
- `sysprof serve --addr 127.0.0.1:8080`: collection plus web UI.
- `sysprof record -o out.jsonl`: one JSON snapshot per interval to a file.
- `sysprof export -i out.jsonl --what categories -o out.csv`: last recorded
  snapshot as CSV (`syscalls`, `processes` or `categories`).
- `serve` also takes `--no-active` and `--unsafe-remote-control`.
- Flags: `--pid`, `--comm`, `--syscall`, `--interval`, `--fake`.

## 9. Active kernel features

The profiler observes. Three more subsystems change behaviour. Each is an
interface with a kernel implementation, a fake (`--fake`), and an
`Unavailable` stand-in that carries the reason, so one missing kernel feature
does not take the dashboard down.

**Shield** (`bpf/shield_lsm.c`, `internal/shield`)
- LSM programs on `bprm_check_security` (exec), `file_open` (open, path via
  `bpf_d_path`) and `ptrace_access_check`. They run before the operation
  and return `-EPERM`, optionally `bpf_send_signal(9)`.
- Rules live in a 16 slot array map, so they change at runtime without
  restarting anything. Matching is by process name (comm), pid and path prefix.
- Counters are kernel side. Interception events come through a ring buffer.
- The daemon's own pid is exempt, and the open path is skipped entirely while
  no open rule exists.
- Simulation: a hidden `__victim` subcommand renames itself `sysprof-victim`
  and tries a shell exec, a canary file open, a ptrace attach and a file whose
  rule is `KILL`. Nothing destructive is touched.

**Bypass** (`bpf/sock_bypass.c`, `internal/sockbypass`)
- `sockops` on the root cgroup puts established loopback sockets in a
  sockhash. `sk_msg` redirects each send to the peer's receive queue
  (`bpf_msg_redirect_hash` with `BPF_F_INGRESS`).
- A `registered` map records which peers are in the sockhash, because a
  redirect to a missing peer drops the data and `sk_msg` cannot release a
  socket reference obtained from a sockhash lookup.
- Toggling flips a flag in a map. Sockets only join while it is on.
- Benchmark: 64 byte TCP ping-pong over a fresh connection, off then on.

**Scheduler** (`internal/scheduler`)
- Honest scope: no `sched_ext`. The policy is the nice value (0, 10, 19) of
  stress workers, and effect is measured with a 1ms sleep overshoot probe.
- The process table is real `/proc` data: nice, CPU, affinity and
  involuntary context switches (preemptions).

**HTTP safety**
- State changing routes need `X-Sysprof-Action: 1` (forces a CORS preflight
  that is never answered), a same origin `Origin`, a loopback `Host` and a
  loopback listen address, unless `--unsafe-remote-control`.

## 10. Constraints and safety

- Needs Linux 5.x+ with BTF and tracefs, and root or `CAP_BPF` +
  `CAP_PERFMON`.
- The web server binds to `127.0.0.1` by default because the tool runs as
  root and exposes system internals.
- The tool excludes its own pid so reading the maps does not show up in the
  results.
- Syscall numbers differ between x86_64 and arm64, so the binary uses the
  table for the architecture it was built for.

## 11. Known limits

- No per call outlier list. Raw events are never streamed, so the UI shows
  per syscall max latency instead.
- Spike detection starts after five intervals, uses the interval p95 (not raw
  calls), and ignores syscalls with fewer than 10 calls in that interval.
- Categories are name based heuristics; an unlisted or new syscall counts as
  `other`.
- The UI filter box only hides rows. For filtered percentiles use the CLI
  flags, which filter before aggregating.
- Percentiles are approximate (log2 buckets).
- The `max` update in the kernel is not atomic, so a race can lose an update.
  It is a hint, not an exact figure.
- Real data needs Linux. On macOS use Docker, a Linux VM, or `--fake`.
- The shield covers exec, open and ptrace only, not mount or unshare. Exec
  matches the path as passed to `execve`, so a relative path or a copy of a
  shell under another name is not caught by a path rule.
- The bypass only accelerates loopback IPv4 TCP opened while it is on, and
  `packets` are `sendmsg` calls, not wire packets.
- The scheduler pillar is nice values plus a jitter probe, not a sched_ext
  scheduler. On a machine with many idle CPUs the improvement is small.

## 12. Related docs

- `README.md`: short overview and API list.
- `USAGE.md`: how to run it on Linux and non Linux machines.
