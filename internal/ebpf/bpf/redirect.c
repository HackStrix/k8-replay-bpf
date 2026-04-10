
//go:build ignore

// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>

// bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h
#include "../headers/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}


// CONSTANS
//
#define ETH_P_IP 0x0800 /* Internet Protocol Packet */


struct event{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Defining a ring buffer map for delivery to userspace go code.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // map type ring buffer
    __uint(max_entries, 256 * 1024);    // 256KB buffer size
    __type(value, struct event);
} events SEC(".maps");


SEC("tc")
int redirect(struct __sk_buff *ctx){




    void *data_end = (void*)(__u64)ctx->data_end;
    void *data = (void*)(__u64)ctx->data;

    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *l4;

    // If this does not have ETH header return 0
    if (ctx->protocol != bpf_htons(ETH_P_IP)) return 0;

    l2 = data;

    // Not sure what this does.
    if ((void *) (l2 + 1) > data_end) return 0;


    l3 = (struct iphdr *)(l2+1);
    
    if ((void *) (l3+1) > data_end) return 0;

    bpf_printk("Got IP Packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);

    // ip header is not of fixed len, 
    int ip_len = l3->ihl * 4;
    l4 = (struct tcphdr *)((void *)l3 + ip_len);

    if ((void *)(l4+1) > data_end) return 0;

    bpf_printk("Got TCP Packet: src_port: %d, dst_port: %d", bpf_ntohs(l4->source), bpf_ntohs(l4->dest));


    //// Setting up ringbuf
    struct event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;
    /// ending ringbuf setup
    
    // pushing data to event
    ev->src_ip = l3->saddr;
    ev->dst_ip = l3->daddr;
    ev->src_port = l4->source;
    ev->dst_port = l4->dest;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}



char __license[] SEC("license") = "GPL";
