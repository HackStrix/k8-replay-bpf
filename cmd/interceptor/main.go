package main

import (
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "bytes"
    "encoding/binary"
    "errors"
    // "time"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
    "github.com/cilium/ebpf/ringbuf"

    bpf "github.com/hackstrix/k8-replay-bpf/internal/ebpf/bytecode"
)

func main() {
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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

    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        log.Fatalf("Creating ringbuf reader failed: %s", err)
    }
    defer rd.Close()

    // this is a goroutine which is just responsible for listening to sigterm and killing the ringbuffer reader
    go func() {
        <- stopper

        if err:= rd.Close(); err != nil {
            log.Fatal("Closing ringbuf reader: %s", err)
        }
    }()

    log.Printf("Waiting for events...")

    var event bpf.RedirectEvent

    for {
        record, err := rd.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}

            log.Printf("Error reading from ringbuf: %s", err)
            continue
        }

        if err:= binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
            log.Printf("Error decoding event: %s", err)
            continue
        }

        log.Printf("Event: %v", event)
    }


}
