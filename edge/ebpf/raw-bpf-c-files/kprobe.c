//go:build ignore

#include "../headers/vmlinux.h" // Requires CO-RE. Do not use raw kernel headers for syscalls.
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// We cannot grab unlimited memory in the kernel. We grab a slice.
#define MAX_PAYLOAD_SIZE 1024

#define DIR_INBOUND 0
#define DIR_OUTBOUND 1

// 5. The Event Structure
struct http_event {
	u32 pid;
	u32 tgid;
	u32 fd;
	u32 len;
	u8 direction; // 0=INBOUND (read), 1=OUTBOUND (write)
	u32 netns_id;
	u64 timestamp;
	char payload[MAX_PAYLOAD_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024); // 1MB buffer
	__type(value, struct http_event);
} events SEC(".maps");

struct config {
	u64 pidns_dev;
	u64 pidns_ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct config);
} config_map SEC(".maps");


struct conn_state {
	u64 last_seen_ns;
};

// 3. Tracking map for active HTTP connections
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
	__type(key, u64);   // tgid << 32 | fd
	__type(value, struct conn_state); // active state
} active_conns SEC(".maps");

struct active_read_args {
	u32 fd;
	u64 buf; // Cast pointer to u64 to avoid bpf2go generation error
};

// 4. Tracking map for active read syscalls (pid_tgid -> args)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64); 
	__type(value, struct active_read_args);
} active_reads SEC(".maps");

// Moved up

// 3. Syscall arguments structure for sys_enter_write
// We must match the kernel's layout exactly. The __pad ensures 8-byte alignment
// for the pointers following syscall_nr.
struct trace_event_raw_sys_enter_write {
	u64 pad;
	int syscall_nr;
	u32 __pad;
	unsigned long fd;
	const char *buf;
	size_t count;
};

struct trace_event_raw_sys_enter_read {
	u64 pad;
	int syscall_nr;
	u32 __pad;
	unsigned int fd;
	const char *buf;
	size_t count;
};

struct trace_event_raw_sys_exit_read {
	u64 pad;
	int syscall_nr;
	u32 __pad;
	long ret;
};

struct trace_event_raw_sys_enter_close {
	u64 pad;
	int syscall_nr;
	u32 __pad;
	unsigned int fd;
};

// 4. Fast-path heuristic filter for HTTP requests
static __always_inline bool is_http_request(const char *buf) {
	char signature[4];
	
	// Safely read the first 4 bytes from user memory
	if (bpf_probe_read_user(&signature, 4, buf) != 0) {
		return false;
	}


	// print signature safely
	// bpf_printk("Signature check: %c%c%c%c", signature[0], signature[1], signature[2], signature[3]);

	// Compare against standard HTTP methods
	if (signature[0] == 'G' && signature[1] == 'E' && signature[2] == 'T' && signature[3] == ' ') return true;
	if (signature[0] == 'P' && signature[1] == 'O' && signature[2] == 'S' && signature[3] == 'T') return true;
	if (signature[0] == 'H' && signature[1] == 'T' && signature[2] == 'T' && signature[3] == 'P') return true; // Catch responses

	return false;
}

// 5. The Tracepoint Hook for Write (Outbound)
static __always_inline int handle_write(unsigned int fd, const char *buf, size_t count) {
	// A. Check if the buffer has any data
	if (count == 0 || !buf) {
		return 0;
	}

	// B. The Filter Logic
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u64 key = (u64)tgid << 32 | fd;

	bool is_new = is_http_request(buf);
	bool is_active = false;

	u64 now = bpf_ktime_get_ns();

	if (is_new) {
		struct conn_state state = {
			.last_seen_ns = now,
		};
		bpf_map_update_elem(&active_conns, &key, &state, BPF_ANY);
		is_active = true;
	} else {
		struct conn_state *state = bpf_map_lookup_elem(&active_conns, &key);
		if (state) {
			is_active = true;
			// Refresh timestamp to stay hot in LRU
			state->last_seen_ns = now;
		}
	}

	if (!is_active) {
		return 0;
	}

	bpf_printk("HTTP Write: PID: %d, FD: %d, New: %d, Count: %d", tgid, fd, is_new, count);

	// C. We have a hit. Reserve memory in the ring buffer.
	struct http_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0; // Buffer full, drop it
	}

	// D. Gather Context
	u32 zero = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &zero);
	struct bpf_pidns_info ns_info = {};
	
	if (cfg && cfg->pidns_ino > 0 && bpf_get_ns_current_pid_tgid(cfg->pidns_dev, cfg->pidns_ino, &ns_info, sizeof(ns_info)) == 0) {
		event->pid = ns_info.pid;
		event->tgid = ns_info.tgid;
	} else {
		// Fallback to host PIDs if config not available
		event->pid = id >> 32;
		event->tgid = id;
	}

	event->fd = fd;
	event->direction = DIR_OUTBOUND;
	
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	event->netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
	
	event->timestamp = now;
	
	// Ensure we don't try to read more than our struct allows or what was written
	event->len = (count < MAX_PAYLOAD_SIZE) ? count : MAX_PAYLOAD_SIZE;

	// E. Safely copy the payload from user-space memory into our event
	bpf_probe_read_user(&event->payload, event->len, buf);

	// F. Ship it
	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_write(struct trace_event_raw_sys_enter_write *ctx) {
	return handle_write(ctx->fd, ctx->buf, ctx->count);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_sendto(struct trace_event_raw_sys_enter_write *ctx) {
	return handle_write(ctx->fd, ctx->buf, ctx->count);
}


// 6. The Tracepoint Hooks for Read (Inbound)
static __always_inline int handle_enter_read(unsigned int fd, const char *buf) {
	u64 id = bpf_get_current_pid_tgid();
	
	struct active_read_args args = {
		.fd = fd,
		.buf = (u64)buf,
	};
	
	bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter_read *ctx) {
	return handle_enter_read(ctx->fd, ctx->buf);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter_read *ctx) {
	return handle_enter_read(ctx->fd, ctx->buf);
}

static __always_inline int handle_exit_read(long ret) {
	u64 id = bpf_get_current_pid_tgid();
	
	struct active_read_args *args = bpf_map_lookup_elem(&active_reads, &id);
	if (!args) {
		return 0;
	}
	
	if (ret <= 0) {
		bpf_map_delete_elem(&active_reads, &id);
		return 0;
	}

	u32 tgid = id >> 32;
	u64 key = (u64)tgid << 32 | args->fd;

	bool is_new = is_http_request((const char *)args->buf);
	bool is_active = false;
	u64 now = bpf_ktime_get_ns();

	if (is_new) {
		struct conn_state state = {
			.last_seen_ns = now,
		};
		bpf_map_update_elem(&active_conns, &key, &state, BPF_ANY);
		is_active = true;
	} else {
		struct conn_state *state = bpf_map_lookup_elem(&active_conns, &key);
		if (state) {
			is_active = true;
			state->last_seen_ns = now;
		}
	}

	if (!is_active) {
		bpf_map_delete_elem(&active_reads, &id);
		return 0;
	}

	bpf_printk("HTTP Read: PID: %d, FD: %d, New: %d, Count: %d", tgid, args->fd, is_new, ret);

	struct http_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		bpf_map_delete_elem(&active_reads, &id);
		return 0;
	}

	u32 zero = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &zero);
	struct bpf_pidns_info ns_info = {};

	if (cfg && cfg->pidns_ino > 0 && bpf_get_ns_current_pid_tgid(cfg->pidns_dev, cfg->pidns_ino, &ns_info, sizeof(ns_info)) == 0) {
		event->pid = ns_info.pid;
		event->tgid = ns_info.tgid;
	} else {
		event->pid = id >> 32;
		event->tgid = id;
	}
	event->fd = args->fd;
	event->direction = DIR_INBOUND;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	event->netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

	event->timestamp = now;
	
	event->len = (ret < MAX_PAYLOAD_SIZE) ? ret : MAX_PAYLOAD_SIZE;
	bpf_probe_read_user(&event->payload, event->len, (const void *)args->buf);

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&active_reads, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit_read *ctx) {
	return handle_exit_read(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit_read *ctx) {
	return handle_exit_read(ctx->ret);
}


// 6. The Close Hook (Cleanup)
SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_close(struct trace_event_raw_sys_enter_close *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u64 key = (u64)tgid << 32 | ctx->fd;

	// Remove from tracking map if present
	bpf_map_delete_elem(&active_conns, &key);
	
	return 0;
}