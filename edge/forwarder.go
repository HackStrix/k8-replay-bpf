package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hackstrix/k8-replay-bpf/pkg/models"
)

// StdoutForwarder is a simple forwarder for MVP/Testing that outputs to standard out.
type StdoutForwarder struct{}

func NewStdoutForwarder() *StdoutForwarder {
	return &StdoutForwarder{}
}

func (s *StdoutForwarder) Start(ctx context.Context) error {
	fmt.Println("StdoutForwarder started")
	return nil
}

func (s *StdoutForwarder) Send(msg models.ProtocolEvent) error {
	// We encode Payload as base64 or custom string format to avoid JSON output messing up raw bytes.
	// But for MVP readability, let's just create a raw log.

	jsonData, err := json.Marshal(struct {
		ConnID    uint64    `json:"conn_id"`
		Direction string    `json:"direction"`
		Timestamp uint64    `json:"timestamp"`
		Payload   string    `json:"payload_snippet"` // Safe string conversion for visual inspection
		Bytes     int       `json:"bytes"`
	}{
		ConnID:    msg.ConnID,
		Direction: msg.Direction.String(),
		Timestamp: msg.Timestamp,
		Payload:   string(msg.Payload),
		Bytes:     len(msg.Payload),
	})

	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, string(jsonData))
	return nil
}

func (s *StdoutForwarder) Close() error {
	fmt.Println("StdoutForwarder closed")
	return nil
}
