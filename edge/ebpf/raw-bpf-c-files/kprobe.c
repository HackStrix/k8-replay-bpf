//go:build ignore

#include "../headers/vmlinux.h" // Requires CO-RE. Do not use raw kernel headers for syscalls.
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// We cannot grab unlimited memory in the kernel. We grab a slice.
#define MAX_PAYLOAD_SIZE 256 

// 1. The Ring Buffer for Userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024); // 1MB buffer
} events SEC(".maps");

// 2. The Event Structure
struct http_event {
	u32 pid;
	u32 tgid;
	u32 fd;
	u32 len;
	char payload[MAX_PAYLOAD_SIZE];
};

// 3. Syscall arguments structure for sys_enter_write
// We must match the kernel's layout exactly. The __pad ensures 8-byte alignment
// for the pointers following syscall_nr.
struct trace_event_raw_sys_enter_write {
	u64 pad;
	int syscall_nr;
	u32 __pad; // 4-byte alignment padding
	unsigned long fd;
	const char *buf;
	size_t count;
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

// 5. The Tracepoint Hook
SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_write(struct trace_event_raw_sys_enter_write *ctx) {

	// A. Check if the buffer has any data
	if (ctx->count == 0 || !ctx->buf) {
		return 0;
	}

	// B. The Filter: If it doesn't start with HTTP signatures, drop it immediately.
	if (!is_http_request(ctx->buf)) {
		return 0;
	}

	bpf_printk("HTTP Request detected! PID: %d, FD: %d, Count: %d", ctx->syscall_nr, ctx->fd, ctx->count);

	// C. We have a hit. Reserve memory in the ring buffer.
	struct http_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0; // Buffer full, drop it
	}

	// D. Gather Context
	u64 id = bpf_get_current_pid_tgid();
	event->pid = id >> 32;
	event->tgid = id;
	event->fd = ctx->fd;
	
	// Ensure we don't try to read more than our struct allows or what was written
	event->len = (ctx->count < MAX_PAYLOAD_SIZE) ? ctx->count : MAX_PAYLOAD_SIZE;

	// E. Safely copy the payload from user-space memory into our event
	bpf_probe_read_user(&event->payload, event->len, ctx->buf);

	// F. Ship it
	bpf_ringbuf_submit(event, 0);

	return 0;
}