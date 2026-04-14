package models

type Direction uint8

const (
	DirInbound  Direction = 0 // Request received by the server
	DirOutbound Direction = 1 // Response sent by the server
)

func (d Direction) String() string {
	switch d {
	case DirInbound:
		return "INBOUND"
	case DirOutbound:
		return "OUTBOUND"
	default:
		return "UNKNOWN"
	}
}

// ProtocolEvent is emitted by the Edge Pipeline directly from eBPF
type ProtocolEvent struct {
	ConnID    uint64
	Direction Direction
	Timestamp uint64
	Payload   []byte // Extracted chunk of the HTTP message
}
