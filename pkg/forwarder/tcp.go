package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/hackstrix/k8-replay-bpf/pkg/models"
)

type TCPForwarder struct {
	addr string
	conn net.Conn
}

func NewTCPForwarder(addr string) *TCPForwarder {
	return &TCPForwarder{
		addr: addr,
	}
}

func (t *TCPForwarder) Start(ctx context.Context) error {
	// Attempt initial connection
	if err := t.connect(); err != nil {
		log.Printf("Warning: TCP forwarder failed initial connection to %s: %v. Will retry on send.", t.addr, err)
	}
	return nil
}

func (t *TCPForwarder) connect() error {
	if t.conn != nil {
		t.conn.Close()
	}
	conn, err := net.DialTimeout("tcp", t.addr, 2*time.Second)
	if err != nil {
		return err
	}
	t.conn = conn
	return nil
}

func (t *TCPForwarder) Send(msg models.ProtocolEvent) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	// Append newline for JSON-lines framing
	data = append(data, '\n')

	if t.conn == nil {
		if err := t.connect(); err != nil {
			return fmt.Errorf("failed to reconnect: %w", err)
		}
	}

	_, err = t.conn.Write(data)
	if err != nil {
		// Try to reconnect once
		t.conn.Close()
		t.conn = nil
		if recErr := t.connect(); recErr == nil {
			_, err = t.conn.Write(data)
		}
	}
	
	return err
}

func (t *TCPForwarder) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}
