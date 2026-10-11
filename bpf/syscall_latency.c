// SPDX-License-Identifier: GPL-2.0
//
// Measures syscall latency per (process, syscall) and keeps the result as a
// log2 histogram inside the kernel. User space only reads the summaries.

#include "headers/common.h"

char __license[] SEC("license") = "GPL";

#define HIST_BUCKETS 32
#define MAX_START    10240 // threads inside a syscall at the same moment
#define MAX_STATS    16384 // distinct (pid, syscall) pairs

// Layout of the raw_syscalls tracepoints. The first 8 bytes are the common
// tracepoint header (see /sys/kernel/tracing/events/raw_syscalls/*/format).
struct sys_enter_ctx {
	__u64 common;
	__s64 id;
	__u64 args[6];
};

struct sys_exit_ctx {
	__u64 common;
	__s64 id;
	__s64 ret;
};

// Written at sys_enter, consumed at sys_exit.
struct start_info {
	__u64 ts;
	__u32 syscall;
	__u32 pad;
};

struct stat_key {
	__u32 pid; // tgid, the "process id" users know
	__u32 syscall;
};

// Mirrored by statVal in internal/collector/ebpf_linux.go: keep in sync.
struct stat_val {
	__u64 count;
	__u64 total_ns;
	__u64 max_ns;
	__u64 hist[HIST_BUCKETS]; // bucket i holds latencies in [2^i, 2^(i+1)) ns
	char  comm[16];
};

// In-flight syscalls. Keyed by pid_tgid (thread id) because many threads of
// one process can be inside the kernel at once.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_START);
	__type(key, __u64);
	__type(value, struct start_info);
} start SEC(".maps");

// Aggregated results, read by the Go collector.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STATS);
	__type(key, struct stat_key);
	__type(value, struct stat_val);
} stats SEC(".maps");

static __always_inline __u32 log2l(__u64 v) {
	__u32 r = 0;
	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8)  { v >>= 8;  r += 8; }
	if (v >> 4)  { v >>= 4;  r += 4; }
	if (v >> 2)  { v >>= 2;  r += 2; }
	if (v >> 1)  { r += 1; }
	return r;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	struct start_info si = {
		.ts = bpf_ktime_get_ns(),
		.syscall = (__u32)ctx->id,
	};
	bpf_map_update_elem(&start, &id, &si, BPF_ANY);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct sys_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();

	// The verifier requires this NULL check. It is also real: the program may
	// have been attached while this thread was already inside a syscall.
	struct start_info *si = bpf_map_lookup_elem(&start, &id);
	if (!si)
		return 0;

	__u64 delta = bpf_ktime_get_ns() - si->ts;
	struct stat_key key = {
		.pid = id >> 32,
		.syscall = si->syscall,
	};
	bpf_map_delete_elem(&start, &id);

	struct stat_val *sv = bpf_map_lookup_elem(&stats, &key);
	if (!sv) {
		struct stat_val zero = {};
		bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
		// NOEXIST: if another CPU created it first, keep theirs.
		bpf_map_update_elem(&stats, &key, &zero, BPF_NOEXIST);
		sv = bpf_map_lookup_elem(&stats, &key);
		if (!sv)
			return 0;
	}

	__u32 slot = log2l(delta);
	if (slot >= HIST_BUCKETS)
		slot = HIST_BUCKETS - 1;

	__sync_fetch_and_add(&sv->count, 1);
	__sync_fetch_and_add(&sv->total_ns, delta);
	__sync_fetch_and_add(&sv->hist[slot], 1);
	// Not atomic: a race can lose a max update, which is fine for a hint.
	if (delta > sv->max_ns)
		sv->max_ns = delta;
	return 0;
}
