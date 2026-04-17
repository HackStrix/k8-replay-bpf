package assembler

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/hackstrix/k8-replay-bpf/pkg/models"
)

type connection struct {
	id             uint64
	reqWriter      *io.PipeWriter
	resWriter      *io.PipeWriter
	ignored        bool
	lastActivity   time.Time
	podName        string
	podNamespace   string
}

type StreamManager struct {
	mu         sync.Mutex
	conns      map[uint64]*connection
	OnRequest  func(req *http.Request, body []byte, podName, podNamespace string)
	OnResponse func(res *http.Response, body []byte, podName, podNamespace string)
}

func NewStreamManager() *StreamManager {
	return &StreamManager{
		conns: make(map[uint64]*connection),
	}
}

func (sm *StreamManager) HandleEvent(event models.ProtocolEvent) {
	sm.mu.Lock()
	conn, exists := sm.conns[event.ConnID]
	if !exists {
		conn = sm.newConnection(event.ConnID)
		sm.conns[event.ConnID] = conn
	}
	
	// Update metadata if it was missing or if it changed (though it shouldn't for the same ConnID)
	if conn.podName == "" && event.PodName != "" {
		conn.podName = event.PodName
		conn.podNamespace = event.PodNamespace
	}

	if conn.ignored {
		sm.mu.Unlock()
		return
	}
	sm.mu.Unlock()

	var err error
	
	// Determine if the payload belongs to the HTTP Request or Response based on Role
	isRequest := false
	if event.Role == models.RoleServer {
		// If we are the Server, inbound traffic is the request, outbound is response
		isRequest = (event.Direction == models.DirInbound)
	} else if event.Role == models.RoleClient {
		// If we are the Client, outbound traffic is the request, inbound is response
		isRequest = (event.Direction == models.DirOutbound)
	} else {
		// Fallback to old behavior if Role is Unknown
		isRequest = (event.Direction == models.DirInbound)
	}

	if isRequest {
		_, err = conn.reqWriter.Write(event.Payload)
	} else {
		_, err = conn.resWriter.Write(event.Payload)
	}

	if err == io.ErrClosedPipe {
		sm.ignoreConnection(event.ConnID)
	} else if err != nil {
		log.Printf("Error writing to pipe for conn %d: %v", event.ConnID, err)
	}
}

func (sm *StreamManager) ignoreConnection(id uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if conn, exists := sm.conns[id]; exists {
		conn.ignored = true
		conn.reqWriter.Close()
		conn.resWriter.Close()
	}
}

func (sm *StreamManager) newConnection(id uint64) *connection {
	reqReader, reqWriter := io.Pipe()
	resReader, resWriter := io.Pipe()

	conn := &connection{
		id:           id,
		reqWriter:    reqWriter,
		resWriter:    resWriter,
		lastActivity: time.Now(),
	}

	// Request Parser Goroutine
	go func() {
		defer reqReader.Close()
		br := bufio.NewReader(reqReader)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				// Stop processing and ignore future chunks if it is not valid plaintext HTTP
				if err != io.EOF && err != io.ErrClosedPipe {
					sm.ignoreConnection(id)
				}
				return
			}
			
			// If it's a proxy CONNECT tunnel, the subsequent bytes are opaque/encrypted
			if req.Method == http.MethodConnect {
				log.Printf("[%d] Ignoring CONNECT tunnel (encrypted).", id)
				sm.ignoreConnection(id)
				return // Let goroutines exit
			}
			
			// Process Request
			// log.Printf("\n=== [Conn %d] NEW HTTP REQUEST ===", id)
			// log.Printf("%s %s %s", req.Method, req.URL.String(), req.Proto)
			// for k, v := range req.Header {
			//	log.Printf("%s: %v", k, v)
			// }
			
			if req.Header.Get("Upgrade") == "websocket" || req.Header.Get("upgrade") == "websocket" {
				log.Printf("[%d] Ignoring WebSocket upgrade.", id)
				sm.ignoreConnection(id)
				return // Let goroutines exit
			}

			// Try to read body
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, _ = io.ReadAll(req.Body)
				req.Body.Close()
			}

			if sm.OnRequest != nil {
				sm.OnRequest(req, bodyBytes, conn.podName, conn.podNamespace)
			}
		}
	}()

	// Response Parser Goroutine
	go func() {
		defer resReader.Close()
		br := bufio.NewReader(resReader)
		for {
			// Note: without the original *http.Request, ParseResponse assumes a standard body (no HEAD restrictions)
			res, err := http.ReadResponse(br, nil)
			if err != nil {
				if err != io.EOF && err != io.ErrClosedPipe {
					sm.ignoreConnection(id)
				}
				return
			}
			
			// Process Response
			// log.Printf("\n=== [Conn %d] NEW HTTP RESPONSE ===", id)
			// log.Printf("%s %s", res.Proto, res.Status)
			
			if res.StatusCode == 101 {
				log.Printf("[%d] Ignoring 101 Switching Protocols.", id)
				sm.ignoreConnection(id)
				return // exit goroutine
			}

			var bodyBytes []byte
			if res.Body != nil {
				bodyBytes, _ = io.ReadAll(res.Body)
				res.Body.Close()
			}

			if sm.OnResponse != nil {
				sm.OnResponse(res, bodyBytes, conn.podName, conn.podNamespace)
			}
		}
	}()

	return conn
}
