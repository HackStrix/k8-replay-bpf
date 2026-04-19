package edge

import (
	"log"
	"sync"
	"time"

	"github.com/hackstrix/k8-replay-bpf/pkg/forwarder"
	"github.com/hackstrix/k8-replay-bpf/pkg/models"
)

// SessionState tracks the components of a single HTTP transaction.
type SessionState struct {
	mu           sync.Mutex
	result       models.SessionResult
	canaryReady  bool
	prodReady    bool
	sent         bool
	createdAt    time.Time
}

func (s *SessionState) UpdateCanary(res CanaryResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result.CanaryResStatus = res.Status
	s.result.CanaryResPayload = res.Payload
	s.result.Latency = res.Latency
	s.canaryReady = true
}

func (s *SessionState) UpdateProd(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result.ProdResStatus = status
	s.result.ProdResPayload = body
	s.prodReady = true
}

// SessionTracker manages multiple in-flight sessions across all connections.
type SessionTracker struct {
	mu    sync.RWMutex
	conns map[uint64][]*SessionState // Concurrent requests on a single connection (queue)
	fwd   forwarder.Forwarder
}

func NewSessionTracker(fwd forwarder.Forwarder) *SessionTracker {
	st := &SessionTracker{
		conns: make(map[uint64][]*SessionState),
		fwd:   fwd,
	}
	go st.cleanupLoop()
	return st
}

func (st *SessionTracker) Push(connID uint64, state *SessionState) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.conns[connID] = append(st.conns[connID], state)
}

func (st *SessionTracker) Pop(connID uint64) *SessionState {
	st.mu.Lock()
	defer st.mu.Unlock()
	queue := st.conns[connID]
	if len(queue) == 0 {
		return nil
	}
	state := queue[0]
	st.conns[connID] = queue[1:]
	if len(st.conns[connID]) == 0 {
		delete(st.conns, connID)
	}
	return state
}

func (st *SessionTracker) Finalize(state *SessionState) {
	state.mu.Lock()
	if state.sent || !state.canaryReady || !state.prodReady {
		state.mu.Unlock()
		return
	}
	state.sent = true
	res := state.result
	state.mu.Unlock()

	if st.fwd != nil {
		log.Printf("[TRACKER] Session complete for ConnID %d. Sending to Collector.", res.ConnID)
		if err := st.fwd.Send(res); err != nil {
			log.Printf("[WARN] Failed to forward final result: %v", err)
		}
	}
}

func (st *SessionTracker) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		st.mu.Lock()
		now := time.Now()
		for connID, queue := range st.conns {
			var newQueue []*SessionState
			for _, state := range queue {
				if now.Sub(state.createdAt) > 30*time.Second {
					// Discard stale sessions to prevent memory bloat
					continue
				}
				newQueue = append(newQueue, state)
			}
			if len(newQueue) == 0 {
				delete(st.conns, connID)
			} else {
				st.conns[connID] = newQueue
			}
		}
		st.mu.Unlock()
	}
}
