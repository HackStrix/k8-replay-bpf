package main

import (
    "log"
    "net"
    // "os"
    // "os/signal"
    "time"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
    bpf "github.com/hackstrix/k8-replay-bpf/internal/ebpf/bytecode"
)

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs bpf.RedirectObjects 
    if err := bpf.LoadRedirectObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close()

    ifname := "ens18" // Change this to an interface on your machine.
    iface, err := net.InterfaceByName(ifname)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach count_packets to the network interface.
    link, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.Redirect,
		Attach:    ebpf.AttachTCXIngress,
	})
    if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
    defer link.Close() 

    log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)


    // sleep for 100 seconds.
    time.Sleep(100 * time.Second)
}
