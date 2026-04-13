package edge
// will be defining the edge server logic here, which is supposed to run as daemon set in kubernetes nodes

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	ebpf "github.com/hackstrix/k8-replay-bpf/edge/ebpf/bytecode"
)

// 1. Map the C struct exactly.
// If the memory layout doesn't match the kernel perfectly, your data will be garbage.
type HTTPEvent struct {
	Pid     uint32
	Tgid    uint32
	Fd      uint32
	Len     uint32
	Payload [256]byte
}

func RunEdge() {
	// Set up a context to handle graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }



	// 2. Load pre-compiled programs and maps into the kernel.
	// bpf2go generated 'loadTracerObjects' for us based on the 'Tracer' prefix above.
	objs := ebpf.KprobeObjects{}
	if err := ebpf.LoadKprobeObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 3. Attach the eBPF program to the tracepoint.
	// We are attaching to syscalls:sys_enter_write
	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceSysWrite, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()
	log.Println("Tracepoint attached. Listening for HTTP writes...")

	// 4. Open the Ring Buffer from the kernel map
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf: %v", err)
	}
	defer rd.Close()

	// Handle background context cancellation to close the reader
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	var event HTTPEvent

	// 5. The Event Loop - This must be extremely fast.
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ring buffer closed, exiting loop.")
				return
			}
			log.Printf("Error reading from ringbuf: %v", err)
			continue
		}

		// 6. Parse the raw bytes into our Go struct
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse ringbuf event: %v", err)
			continue
		}

		// 7. Safely extract only the populated part of the payload
		// Event.Len tells us exactly how much of the 256-byte array is valid.
		actualPayload := string(event.Payload[:event.Len])

		// For now, we just print. In production, this goes to the Reassembler.
		fmt.Printf("-----------------------------------\n")
		fmt.Printf("[PID: %d] [FD: %d] [Bytes: %d]\n", event.Pid, event.Fd, event.Len)
		fmt.Printf("Payload:\n%s\n", actualPayload)
	}
}