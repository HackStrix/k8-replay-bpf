package edge
// will be defining the edge server logic here, which is supposed to run as daemon set in kubernetes nodes

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	ebpf_bytecode "github.com/hackstrix/k8-replay-bpf/edge/ebpf/bytecode"
)

type ConnState struct {
	LastSeenNs uint64
}

// 1. Map the C struct exactly.
// If the memory layout doesn't match the kernel perfectly, your data will be garbage.
type HTTPEvent struct {
	Pid       uint32
	Tgid      uint32
	Fd        uint32
	Len       uint32
	Direction uint8
	_         [7]byte // Padding to 8-byte boundary
	Timestamp uint64
	Payload   [1024]byte
}

func RunEdge() {
	forwarder := NewStdoutForwarder()
	if err := forwarder.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start forwarder: %v", err)
	}
	defer forwarder.Close()

	// Set up a context to handle graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }



	// 2. Load pre-compiled programs and maps into the kernel.
	// bpf2go generated 'loadTracerObjects' for us based on the 'Tracer' prefix above.
	objs := ebpf_bytecode.KprobeObjects{}
	if err := ebpf_bytecode.LoadKprobeObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceSysWrite, nil)
	if err != nil {
		log.Fatalf("Failed to attach write tracepoint: %v", err)
	}
	defer tp.Close()

	tpReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceSysEnterRead, nil)
	if err != nil {
		log.Fatalf("Failed to attach read enter tracepoint: %v", err)
	}
	defer tpReadEnter.Close()

	tpReadExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TraceSysExitRead, nil)
	if err != nil {
		log.Fatalf("Failed to attach read exit tracepoint: %v", err)
	}
	defer tpReadExit.Close()

	tpClose, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceSysClose, nil)
	if err != nil {
		log.Fatalf("Failed to attach close tracepoint: %v", err)
	}
	defer tpClose.Close()

	log.Println("Tracepoints attached. Listening for HTTP traffic...")

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
		// Event.Len tells us exactly how much of the 1024-byte array is valid.
		actualPayload := event.Payload[:event.Len]

		connID := (uint64(event.Tgid) << 32) | uint64(event.Fd)

		protoEvent := ProtocolEvent{
			ConnID:    connID,
			Direction: Direction(event.Direction),
			Timestamp: event.Timestamp,
			Payload:   actualPayload,
		}

		if err := forwarder.Send(protoEvent); err != nil {
			log.Printf("Failed to forward event: %v", err)
		}
	}
}
