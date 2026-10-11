# Using sysprof

sysprof needs a Linux kernel to collect real data (eBPF does not exist on
macOS or Windows). Pick the section for your machine.

## Requirements (Linux)

- Kernel 5.x or newer, with BTF: `ls /sys/kernel/btf/vmlinux` must exist
- Root, or `CAP_BPF` and `CAP_PERFMON`
- tracefs mounted: `sudo mount -t tracefs nodev /sys/kernel/tracing` if missing
- Go 1.26+ to build (no clang needed, the compiled eBPF object is committed)

## On a Linux machine

```
git clone https://github.com/ASHUTOSH-SWAIN-GIT/sysprof
cd sysprof
make build
```

Run one of:

```
sudo bin/sysprof top                          # live terminal table
sudo bin/sysprof serve                        # web UI on http://127.0.0.1:8080
sudo bin/sysprof record -o out.jsonl          # one JSON snapshot per interval
```

Generate some load in another terminal so there is something to see:

```
dd if=/dev/zero of=/tmp/x bs=4k count=50000 conv=fsync
find /usr -xdev > /dev/null
```

## On macOS or Windows

There are three options. Only options 1 and 2 give real data.

### 1. Docker (quickest, Docker Desktop required)

```
./scripts/demo-docker.sh
```

Then open http://127.0.0.1:8080. This builds the Linux binary, starts a
privileged container inside Docker's Linux VM, runs a small workload and
serves the UI.

- It profiles the Docker VM, not your Mac apps. macOS processes are invisible
  to any Linux kernel.
- Stop it with Ctrl+C.

### 2. A Linux VM (best for demos)

Use Lima, OrbStack, UTM or Multipass, then follow the Linux steps above inside
the VM. Or build on the Mac and copy the binary in:

```
make build-linux                  # GOARCH=amd64 make build-linux on Intel Macs
# copy bin/sysprof-linux into the VM, then inside the VM:
sudo ./sysprof-linux serve --addr 0.0.0.0:8080
```

Ports are forwarded to `localhost` by most VM tools, so the UI opens in your
Mac browser. Bind to `0.0.0.0` only inside a VM you trust, the tool exposes
system internals.

### 3. Demo data (no Linux at all)

```
make demo                         # or: bin/sysprof top --fake
```

Generated numbers, useful for working on the CLI and UI only.

## Active controls (shield, bypass, scheduler)

Open the dashboard (`serve`). The three panels at the top are live.

| Panel | Try this | Needs |
| --- | --- | --- |
| Shield | click Simulate attack, then watch the blocked counters | `bpf` in `/sys/kernel/security/lsm` |
| Bypass | click Run benchmark, toggle Bypass ON/OFF | cgroup v2 at `/sys/fs/cgroup` |
| Scheduler | click Inject CPU load, then switch the policy | any Linux |

- A panel that cannot run shows `unavailable` and the reason; the rest keep working.
- `--fake` makes all three simulated (badge says so), useful on a Mac.
- `--no-active` loads only the profiler.
- Custom shield rules: process name, pid and path prefix, for `exec`, `open`
  or `ptrace`. Rules for all processes need a specific path so you cannot
  block the whole system. They are removed when sysprof exits.
- The benchmark and Inject CPU load run real work on the machine
  (about 10 seconds and 20 seconds).
- If `bpf` is missing from the LSM list, boot with
  `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` (adjust to your distro).
- Binding `--addr` to a non-loopback address disables state changing requests
  unless you also pass `--unsafe-remote-control`.

## Flags

| Flag | Meaning |
| --- | --- |
| `--pid N` | only this process id |
| `--comm name` | only processes whose name contains this |
| `--syscall name` | only this syscall, e.g. `read` |
| `--interval 500ms` | how often the kernel maps are read (default 1s) |
| `--fake` | use generated data instead of eBPF |
| `--addr host:port` | `serve` only, default `127.0.0.1:8080` |
| `--no-active` | `serve` only, skip shield, bypass and scheduler |
| `--unsafe-remote-control` | `serve` only, allow changes from non-loopback listen addresses |
| `-o file` | `record` only, default `sysprof.jsonl` |

## Reading the output

- **COUNT / CALLS/S**: total calls and the rate over the last interval.
- **TOTAL**: time spent in the syscall across all calls. Sort by this to find
  what costs the most overall.
- **AVG, P50, P95, P99, MAX**: latency. Percentiles are estimated from log2
  buckets, so they are accurate to within one power of two.
- **wait tag**: blocking syscalls such as `futex`, `epoll_wait`, `nanosleep`.
  Long latency is expected for them, it does not mean slowness.
- In the web UI, click a syscall row to see its histogram and its
  p50/p95/p99 over time.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `load objects (need root...)` | run with `sudo` |
| `attach sys_enter (is tracefs mounted?)` | `sudo mount -t tracefs nodev /sys/kernel/tracing` |
| `eBPF is not available on darwin` | not on Linux, use Docker, a VM, or `--fake` |
| No `/sys/kernel/btf/vmlinux` | kernel built without BTF, use a newer distro kernel |
| Empty table in Docker | workload not started yet, wait a few seconds |
| Shield `unavailable`, attach LSM failed | `bpf` is not in `/sys/kernel/security/lsm`, see above |
| Bypass `unavailable`, attach sockops failed | cgroup v2 is not mounted at `/sys/fs/cgroup` |
| Bypass shows no connections | only loopback TCP connections opened after the bypass was on are accelerated |
| 403 on a POST | missing `X-Sysprof-Action: 1`, cross origin request, or non-loopback listen address |

## Changing the eBPF program

Edit a file in `bpf/`, then `make generate` (uses clang and libbpf-dev on
Linux, a Docker container on macOS) and commit the regenerated `*_bpfel.*` files.
