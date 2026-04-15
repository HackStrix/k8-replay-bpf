package models

import "time"

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
	ConnID       uint64
	Direction    Direction
	Timestamp    uint64
	Payload      []byte // Extracted chunk of the HTTP message
	PodName      string // Associated Pod Name
	PodNamespace string // Associated Pod Namespace
	NetnsID      uint32 // Network Namespace ID
}

// SessionResult represents a fully completed replay lifecycle.
// Sent by the Edge daemon to the Collector for dashboarding/diffing.
type SessionResult struct {
	ConnID           uint64        `json:"conn_id"`
	ProdReqMethod    string        `json:"prod_req_method"`
	ProdReqURL       string        `json:"prod_req_url"`
	ProdResStatus    int           `json:"prod_res_status"`
	CanaryResStatus  int           `json:"canary_res_status"`
	CanaryResPayload []byte        `json:"canary_res_payload"`
	Latency          time.Duration `json:"latency"`
}
