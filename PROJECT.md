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
| `bpf/headers/` | vendored eBPF helper headers (from cilium/ebpf examples) |
| `internal/collector/ebpf_linux.go` | loads and attaches the program, reads `stats` (Linux only) |
| `internal/collector/fake.go` | generated demo data for any OS |
| `internal/collector/syscalllatency_bpfel.*` | generated Go bindings and compiled object (committed) |
| `internal/model/` | shared types and percentile estimation |
| `internal/store/` | filters, interval diffs, per syscall and per process stats, history, subscribers |
| `internal/server/` | `/api/snapshot`, `/api/history`, `/api/processes`, `/stream` (SSE), static UI |
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
- Flags: `--pid`, `--comm`, `--syscall`, `--interval`, `--fake`.

## 9. Constraints and safety

- Needs Linux 5.x+ with BTF and tracefs, and root or `CAP_BPF` +
  `CAP_PERFMON`.
- The web server binds to `127.0.0.1` by default because the tool runs as
  root and exposes system internals.
- The tool excludes its own pid so reading the maps does not show up in the
  results.
- Syscall numbers differ between x86_64 and arm64, so the binary uses the
  table for the architecture it was built for.

## 10. Known limits

- No per call outlier list. Raw events are never streamed, so the UI shows
  per syscall max latency instead.
- The UI filter box only hides rows. For filtered percentiles use the CLI
  flags, which filter before aggregating.
- Percentiles are approximate (log2 buckets).
- The `max` update in the kernel is not atomic, so a race can lose an update.
  It is a hint, not an exact figure.
- Real data needs Linux. On macOS use Docker, a Linux VM, or `--fake`.

## 11. Related docs

- `README.md`: short overview and API list.
- `USAGE.md`: how to run it on Linux and non Linux machines.
