package collector

import (
	"encoding/json"
	"io"
	"log"
	"net"

	"github.com/hackstrix/k8-replay-bpf/pkg/models"
)

type Server struct {
	addr    string
	streams *StreamManager
}

func NewServer(addr string) *Server {
	return &Server{
		addr:    addr,
		streams: NewStreamManager(),
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
		var event models.ProtocolEvent
		if err := decoder.Decode(&event); err != nil {
			if err != io.EOF {
				log.Printf("Error decoding event: %v", err)
			}
			break
		}

		s.streams.HandleEvent(event)
	}
	log.Printf("Edge client disconnected")
}
