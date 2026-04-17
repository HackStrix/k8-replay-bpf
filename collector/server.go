package collector

import (
	"encoding/json"
	"io"
	"log"
	"net"

	"github.com/hackstrix/k8-replay-bpf/pkg/models"
)

type Server struct {
	addr string
}

func NewServer(addr string) *Server {
	return &Server{
		addr: addr,
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	log.Printf("Collector listening on %s", s.addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("Edge client connected from %s", conn.RemoteAddr())

	decoder := json.NewDecoder(conn)
	for {
		var result models.SessionResult
		if err := decoder.Decode(&result); err != nil {
			if err != io.EOF {
				log.Printf("Error decoding event: %v", err)
			}
			break
		}

		log.Printf("\n=== [SaaS Collector] New Result for ConnID: %d ===", result.ConnID)
		log.Printf("Request: %s %s", result.ProdReqMethod, result.ProdReqURL)
		log.Printf("Prod Res: %d | Canary Res: %d", result.ProdResStatus, result.CanaryResStatus)
		log.Printf("Latency: %v", result.Latency)
		
		if len(result.CanaryResPayload) > 0 {
			// Trim payload for display safety
			payloadStr := string(result.CanaryResPayload)
			if len(payloadStr) > 300 {
				payloadStr = payloadStr[:300] + "...(truncated)"
			}
			log.Printf("Canary Body:\n%s", payloadStr)
		}
		log.Printf("====================================================\n")
	}
	log.Printf("Edge client disconnected")
}