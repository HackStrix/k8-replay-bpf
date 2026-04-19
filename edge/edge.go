package edge
// will be defining the edge server logic here, which is supposed to run as daemon set in kubernetes nodes

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"net/http"
	"os/signal"
	"syscall"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	ebpf_bytecode "github.com/hackstrix/k8-replay-bpf/edge/ebpf/bytecode"
	"github.com/hackstrix/k8-replay-bpf/pkg/assembler"
	"github.com/hackstrix/k8-replay-bpf/pkg/forwarder"
	"github.com/hackstrix/k8-replay-bpf/pkg/k8s"
	"github.com/hackstrix/k8-replay-bpf/pkg/models"
	"strings"
	"time"
	"sync"
	"github.com/cilium/ebpf"
)

type ConnState struct {
	LastSeenNs uint64
}


// 1. Map the C struct exactly.
// If the memory layout doesn't match the kernel perfectly, your data will be garbage.
type HTTPEvent struct {
	Pid         uint32
	Tgid        uint32
	Fd          uint32
	Len         uint32
	Direction   uint8
	Role        uint8
	_           [2]byte // Padding to 4-byte boundary
	NetnsID     uint32  // Network Namespace ID
	Timestamp   uint64
	Payload     [1024]byte
}

func RunEdge() {

	// Forwarder configuration for sending diffs/summaries to SaaS Collector
	// 1. Initialize Forwarder if collector address is provided
	var fwd forwarder.Forwarder
	collectorAddr := os.Getenv("COLLECTOR_ADDR")
	if collectorAddr != "" {
		log.Printf("[INFO] Initializing Forwarder to Collector: %s", collectorAddr)
		fwd = forwarder.NewTCPForwarder(collectorAddr)
		if err := fwd.Start(context.Background()); err != nil {
			log.Printf("[WARN] Failed to start Forwarder: %v", err)
		} else {
			defer fwd.Close()
		}
	} else {
		log.Println("[INFO] No COLLECTOR_ADDR provided. Reporting disabled.")
	}

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

	// Initialize config map for namespace-aware PIDs
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		log.Printf("[WARN] Failed to stat /proc/self/ns/pid: %v. Namespace-aware PIDs may not work.", err)
	} else {
		cfg := ebpf_bytecode.KprobeConfig{
			PidnsDev: uint64(st.Dev),
			PidnsIno: uint64(st.Ino),
		}
		if err := objs.ConfigMap.Update(uint32(0), &cfg, ebpf.UpdateAny); err != nil {
			log.Printf("[WARN] Failed to update BPF config map: %v", err)
		} else {
			log.Printf("[INFO] Initialized BPF PID namespace config: dev=%d, ino=%d", st.Dev, st.Ino)
		}
	}

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

	tpRecvfromEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TraceSysEnterRecvfrom, nil)
	if err != nil {
		log.Fatalf("Failed to attach recvfrom enter tracepoint: %v", err)
	}
	defer tpRecvfromEnter.Close()

	tpRecvfromExit, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.TraceSysExitRecvfrom, nil)
	if err != nil {
		log.Fatalf("Failed to attach recvfrom exit tracepoint: %v", err)
	}
	defer tpRecvfromExit.Close()

	tpSendtoEnter, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSysSendto, nil)
	if err != nil {
		log.Fatalf("Failed to attach sendto enter tracepoint: %v", err)
	}
	defer tpSendtoEnter.Close()

	tpAccept, err := link.Tracepoint("syscalls", "sys_exit_accept", objs.TraceSysExitAccept, nil)
	if err != nil {
		log.Printf("[WARN] Failed to attach accept tracepoint: %v (May not support Role mapping)", err)
	} else {
		defer tpAccept.Close()
	}

	tpAccept4, err := link.Tracepoint("syscalls", "sys_exit_accept4", objs.TraceSysExitAccept4, nil)
	if err != nil {
		log.Printf("[WARN] Failed to attach accept4 tracepoint: %v (May not support Role mapping)", err)
	} else {
		defer tpAccept4.Close()
	}

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

	canaryURL := os.Getenv("CANARY_URL")
	if canaryURL == "" {
		// Default to the in-cluster service address of the canary
		canaryURL = "http://sample-server-canary-service.default.svc.cluster.local:8080"
	}

	replayEngine, err := NewReplayEngine(canaryURL)
	if err != nil {
		log.Fatalf("Invalid canary URL: %v", err)
	}

	streamManager := assembler.NewStreamManager()

	mapper, err := k8s.NewPodMapper(10 * time.Second)
	if err != nil {
		log.Printf("[WARN] Failed to initialize Pod Mapper: %v. Running without Pod metadata.", err)
	} else {
		log.Printf("[INFO] Pod Mapper initialized successfully for node: %s", os.Getenv("NODE_NAME"))
	}

	// 5. Initialize the Session Tracker to bridge Request and Response paths
	tracker := NewSessionTracker(fwd)

	// Local Smart Proxy Replay Trigger
	streamManager.OnRequest = func(connID uint64, req *http.Request, body []byte, podName, podNamespace string) {
		// Check if this request is targeted at our production deployment
		isProd := strings.HasPrefix(podName, "sample-server-prod")
		
		if isProd {
			log.Printf("[EDGE] Hooked PROD Request: %s %s from %s/%s. Initiating multi-path tracking.", req.Method, req.URL.String(), podNamespace, podName)
			
			session := &SessionState{
				result: models.SessionResult{
					ConnID:        connID,
					ProdReqMethod: req.Method,
					ProdReqURL:    req.URL.String(),
				},
				createdAt: time.Now(),
			}
			
			tracker.Push(connID, session)

			// Trigger Canary Path (Concurrent)
			replayEngine.FireAndForget(req, body, connID, func(res CanaryResult) {
				session.UpdateCanary(res)
				tracker.Finalize(session)
			})
		}
	}

	streamManager.OnResponse = func(connID uint64, res *http.Response, body []byte, podName, podNamespace string) {
		if strings.HasPrefix(podName, "sample-server-prod") {
			log.Printf("[EDGE] Hooked PROD Response: %d %s for ConnID %d", res.StatusCode, res.Status, connID)
			
			// Match with the oldest pending request on this connection
			session := tracker.Pop(connID)
			if session != nil {
				session.UpdateProd(res.StatusCode, body)
				tracker.Finalize(session)
			} else {
				log.Printf("[WARN] Orphaned response for ConnID %d (no matching request found)", connID)
			}
		}
	}

	var event HTTPEvent

	// Failure tracking for mapper logs to avoid spam
	var lastLoggedFailure sync.Map // map[uint32]time.Time

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
		actualPayload := event.Payload[:event.Len]
		connID := (uint64(event.Tgid) << 32) | uint64(event.Fd)

		protoEvent := models.ProtocolEvent{
			ConnID:    connID,
			Direction: models.Direction(event.Direction),
			Role:      models.Role(event.Role),
			Timestamp: event.Timestamp,
			Payload:   actualPayload,
			NetnsID:   event.NetnsID,
		}

		// 8. Enrich with Pod Metadata if mapper is available
		if mapper != nil {
			// Now using NetnsID as the primary lookup method
			if pod, err := mapper.GetPodByNetnsID(event.NetnsID); err == nil {
				protoEvent.PodName = pod.Name
				protoEvent.PodNamespace = pod.Namespace
				if !strings.HasPrefix(pod.Name, "ebpf-repeater") {
					log.Printf("[EDGE] Event matched Pod: %s/%s (NetnsID: %d, PID: %d)", pod.Namespace, pod.Name, event.NetnsID, event.Pid)
				}
				lastLoggedFailure.Delete(event.NetnsID)
			} else {
				// Avoid spamming logs for the same NetnsID failure
				now := time.Now()
				if last, ok := lastLoggedFailure.Load(event.NetnsID); !ok || now.Sub(last.(time.Time)) > 1*time.Minute {
					log.Printf("[DEBUG] NetnsID resolution failed for %d: %v. (Suppressed for 1m)", event.NetnsID, err)
					lastLoggedFailure.Store(event.NetnsID, now)
				}
			}
		}

		streamManager.HandleEvent(protoEvent)
	}
}
