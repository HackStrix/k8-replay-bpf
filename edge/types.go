package edge

import (
	"context"

	"github.com/hackstrix/k8-replay-bpf/pkg/models"
)

// Forwarder interface for sending data to the diff layer
type Forwarder interface {
	Start(ctx context.Context) error
	Send(msg models.ProtocolEvent) error
	Close() error
}
