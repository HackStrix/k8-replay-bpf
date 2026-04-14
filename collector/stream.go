package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
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
}

type StreamManager struct {
	mu    sync.Mutex
	conns map[uint64]*connection
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
	if conn.ignored {
		sm.mu.Unlock()
		return
	}
	sm.mu.Unlock()

	var err error
	if event.Direction == models.DirInbound {
		// INBOUND to the pod denotes the HTTP Request
		_, err = conn.reqWriter.Write(event.Payload)
	} else {
		// OUTBOUND from the pod denotes the HTTP Response
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
			log.Printf("\n=== [Conn %d] NEW HTTP REQUEST ===", id)
			log.Printf("%s %s %s", req.Method, req.URL.String(), req.Proto)
			for k, v := range req.Header {
				log.Printf("%s: %v", k, v)
			}
			
			if req.Header.Get("Upgrade") == "websocket" || req.Header.Get("upgrade") == "websocket" {
				log.Printf("[%d] Ignoring WebSocket upgrade.", id)
				sm.ignoreConnection(id)
				return // Let goroutines exit
			}

			// Try to read body for display
			if req.Body != nil {
				bodyBytes, _ := io.ReadAll(req.Body)
				req.Body.Close()
				if len(bodyBytes) > 0 {
					log.Printf("\n[Body: %d bytes]\n%s", len(bodyBytes), string(bytes.ReplaceAll(bodyBytes, []byte("\r\n"), []byte(" "))))
				}
			}
			log.Printf("===================================\n")
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
			log.Printf("\n=== [Conn %d] NEW HTTP RESPONSE ===", id)
			log.Printf("%s %s", res.Proto, res.Status)
			
			if res.StatusCode == 101 {
				log.Printf("[%d] Ignoring 101 Switching Protocols.", id)
				sm.ignoreConnection(id)
				return // exit goroutine
			}

			if res.Body != nil {
				bodyBytes, _ := io.ReadAll(res.Body)
				res.Body.Close()
				
				// Attempt nicely format JSON response body if possible
				var prettyJSON bytes.Buffer
				if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
					log.Printf("\n%s", prettyJSON.String())
				} else if len(bodyBytes) > 0 {
					log.Printf("\n[Body: %d bytes]\n%s", len(bodyBytes), string(bytes.ReplaceAll(bodyBytes, []byte("\r\n"), []byte(" "))))
				}
			}
			log.Printf("====================================\n")
		}
	}()

	return conn
}
