// SPDX-License-Identifier: GPL-2.0
//
// Active syscall shield: BPF LSM hooks that deny exec, open and ptrace for
// processes matching rules pushed from user space. The decision is made in the
// kernel before the operation happens, and rules can change at runtime.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

#define MAX_RULES 16
#define MAX_PATH  64
#define EPERM     1

enum { KIND_EXEC = 1, KIND_OPEN = 2, KIND_PTRACE = 3 };
enum { ACTION_EPERM = 1, ACTION_KILL = 2 };

// Mirrored by kernelRule in internal/shield/shield_linux.go: keep in sync.
struct rule {
	__u32 pid;      // 0 = any
	__u8  active;
	__u8  kind;
	__u8  action;
	__u8  path_len; // 0 = any path
	char  comm[16]; // empty = any
	char  path[MAX_PATH];
};

struct event {
	__u64 ts;
	__u32 pid;
	__u32 rule;
	__u8  kind;
	__u8  action;
	char  comm[16];
	char  path[MAX_PATH];
};

// Minimal kernel struct definitions. CO-RE relocates the field offsets to the
// running kernel, so no vmlinux.h is needed.
struct path {
	void *mnt;
	void *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
} __attribute__((preserve_access_index));

struct linux_binprm {
	const char *filename;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct rule);
} rules SEC(".maps");

// Per rule blocked counters.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, __u64);
} blocked SEC(".maps");

// [0] = tgid that is never blocked (the daemon itself)
// [1] = number of active open rules, lets the hot open path skip d_path
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

// comm is zero padded on both sides (rules from Go, bpf_get_current_comm),
// so two 8 byte compares are enough and the verifier sees no loop.
static __always_inline int comm_match(const char *want, const char *have) {
	const __u64 *w = (const __u64 *)want;
	const __u64 *h = (const __u64 *)have;
	if (w[0] == 0 && w[1] == 0)
		return 1;
	return w[0] == h[0] && w[1] == h[1];
}

static __always_inline int path_match(const struct rule *r, const char *path) {
	__u32 n = r->path_len;
#pragma unroll
	for (int i = 0; i < MAX_PATH; i++) {
		if (i < n && r->path[i] != path[i])
			return 0;
	}
	return 1;
}

// Returns -EPERM when a rule matches, 0 otherwise. path may be NULL (ptrace).
static __always_inline int enforce(__u8 kind, const char *path) {
	__u32 zero = 0;
	__u64 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 *self = bpf_map_lookup_elem(&config, &zero);
	if (self && *self == tgid)
		return 0;

	char comm[16] __attribute__((aligned(8)));
	bpf_get_current_comm(&comm, sizeof(comm));

#pragma unroll
	for (int slot = 0; slot < MAX_RULES; slot++) {
		__u32 i = slot; // own copy: the helper key must not alias the counter
		struct rule *r = bpf_map_lookup_elem(&rules, &i);
		if (!r || !r->active || r->kind != kind)
			continue;
		if (r->pid && r->pid != tgid)
			continue;
		if (!comm_match(r->comm, comm))
			continue;
		if (path && !path_match(r, path))
			continue;

		__u64 *cnt = bpf_map_lookup_elem(&blocked, &i);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);

		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->ts = bpf_ktime_get_ns();
			e->pid = tgid;
			e->rule = i;
			e->kind = kind;
			e->action = r->action;
			__builtin_memcpy(e->comm, comm, sizeof(comm));
			e->path[0] = 0;
			if (path)
				bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
			bpf_ringbuf_submit(e, 0);
		}
		if (r->action == ACTION_KILL)
			bpf_send_signal(9);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/bprm_check_security")
int shield_exec(unsigned long long *ctx) {
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[0];
	char path[MAX_PATH] = {};
	bpf_probe_read_kernel_str(path, sizeof(path), bprm->filename);
	return enforce(KIND_EXEC, path);
}

SEC("lsm/file_open")
int shield_open(unsigned long long *ctx) {
	__u32 one = 1;
	__u64 *open_rules = bpf_map_lookup_elem(&config, &one);
	if (!open_rules || *open_rules == 0)
		return 0;

	struct file *file = (struct file *)ctx[0];
	char path[MAX_PATH] = {};
	if (bpf_d_path(&file->f_path, path, sizeof(path)) < 0)
		return 0;
	return enforce(KIND_OPEN, path);
}

SEC("lsm/ptrace_access_check")
int shield_ptrace(unsigned long long *ctx) {
	return enforce(KIND_PTRACE, 0);
}
