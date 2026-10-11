// SPDX-License-Identifier: GPL-2.0
//
// TCP/IP bypass for loopback connections. A sockops program registers every
// established loopback socket in a sockhash. An sk_msg program then redirects
// each sendmsg straight into the peer socket's receive queue, skipping the TCP
// transmit path, netfilter and the loopback device.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define AF_INET 2

// All fields in host byte order except the IPs, which stay as the kernel
// provides them (consistent on both sides, which is all the lookup needs).
struct sock_key {
	__u32 sip;
	__u32 dip;
	__u32 sport;
	__u32 dport;
};

// Mirrored by connStat in internal/sockbypass/bypass_linux.go.
struct conn_stat {
	__u64 messages;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 4096);
	__type(key, struct sock_key);
	__type(value, int);
} sockhash SEC(".maps");

// [0] = 1 when the bypass is on. Toggled from user space at runtime.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} enabled SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct sock_key);
	__type(value, struct conn_stat);
} conns SEC(".maps");

// Keys of sockets that are in sockhash. sk_msg checks it before redirecting:
// a sockhash lookup would hand back a referenced socket that sk_msg programs
// cannot release, and a redirect to a missing peer drops the message.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock_key);
	__type(value, __u8);
} registered SEC(".maps");

#define TCP_CLOSE 7

static __always_inline int is_on(void) {
	__u32 zero = 0;
	__u32 *on = bpf_map_lookup_elem(&enabled, &zero);
	return on && *on;
}

static __always_inline int is_loopback(__u32 ip) {
	return (bpf_ntohl(ip) >> 24) == 127;
}

SEC("sockops")
int bypass_sockops(struct bpf_sock_ops *skops) {
	if (skops->family != AF_INET)
		return 0;

	struct sock_key key = {
		.sip = skops->local_ip4,
		.dip = skops->remote_ip4,
		.sport = skops->local_port,
		.dport = bpf_ntohl(skops->remote_port),
	};

	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
		if (!is_on())
			return 0;
		if (!is_loopback(skops->local_ip4) || !is_loopback(skops->remote_ip4))
			return 0;
		if (bpf_sock_hash_update(skops, &sockhash, &key, BPF_NOEXIST) == 0) {
			__u8 one = 1;
			bpf_map_update_elem(&registered, &key, &one, BPF_ANY);
			// Get told when the socket closes so the entry can go.
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
		}
		break;
	}
	case BPF_SOCK_OPS_STATE_CB:
		if (skops->args[1] == TCP_CLOSE)
			bpf_map_delete_elem(&registered, &key);
		break;
	}
	return 0;
}

SEC("sk_msg")
int bypass_msg(struct sk_msg_md *msg) {
	if (msg->family != AF_INET || !is_on())
		return SK_PASS;

	// The peer registered itself under its own (local, remote) view, which
	// is our (remote, local) view.
	struct sock_key peer = {
		.sip = msg->remote_ip4,
		.dip = msg->local_ip4,
		.sport = bpf_ntohl(msg->remote_port),
		.dport = msg->local_port,
	};

	// bpf_msg_redirect_hash drops the message if the peer is missing (for
	// example it connected before we attached), so check first and fall back
	// to the normal stack.
	if (!bpf_map_lookup_elem(&registered, &peer))
		return SK_PASS;

	struct sock_key self = {
		.sip = msg->local_ip4,
		.dip = msg->remote_ip4,
		.sport = msg->local_port,
		.dport = bpf_ntohl(msg->remote_port),
	};
	struct conn_stat *cs = bpf_map_lookup_elem(&conns, &self);
	if (cs) {
		__sync_fetch_and_add(&cs->messages, 1);
		__sync_fetch_and_add(&cs->bytes, msg->size);
	} else {
		struct conn_stat init = { .messages = 1, .bytes = msg->size };
		bpf_map_update_elem(&conns, &self, &init, BPF_NOEXIST);
	}

	return bpf_msg_redirect_hash(msg, &sockhash, &peer, BPF_F_INGRESS);
}
