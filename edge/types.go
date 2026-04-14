package edge

import (
	"context"
)

// Forwarder interface for sending data to the diff/saas layer
type Forwarder interface {
	Start(ctx context.Context) error
	Send(msg any) error
	Close() error
}
