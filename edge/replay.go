package edge

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

)

// ReplayEngine handles safely transmitting captured production requests
// to the designated canary environment with minimal overhead.
type ReplayEngine struct {
	client    *http.Client
	canaryURL *url.URL
}

func NewReplayEngine(targetURL string) (*ReplayEngine, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Highly optimized connection pooling for HTTP Replays
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // Keep raw compression headers if they exist
	}

	return &ReplayEngine{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second, // Don't let canary timeouts bleed into prod memory
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't safely follow redirects, mirror exactly
			},
		},
		canaryURL: parsed,
	}, nil
}

// CanaryResult is a subset of SessionResult for the canary replay.
type CanaryResult struct {
	Status  int
	Payload []byte
	Latency time.Duration
	Error   error
}

// FireAndForget takes an assembled production request and fires it at the canary asynchronously.
func (r *ReplayEngine) FireAndForget(prodReq *http.Request, body []byte, connID uint64, onDone func(CanaryResult)) {
	// Execute the replay strictly in a background goroutine so we
	// NEVER block the BPF ringbuffer or the Go parsers.
	go func() {
		start := time.Now()
		
		// 1. Clone the Request cleanly
		req := prodReq.Clone(context.Background())
		
		// 2. Attach the fully re-buffered body
		if len(body) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(body))
			// Ensure ContentLength is exact
			req.ContentLength = int64(len(body))
		} else {
			req.Body = nil
			req.ContentLength = 0
		}

		// 3. Rewrite URL and Host to point to the Canary
		req.URL.Scheme = r.canaryURL.Scheme
		req.URL.Host = r.canaryURL.Host
		// The req.URL.Path stays exactly the same as the original production request
		req.Host = r.canaryURL.Host // Critical for Ingress/API gateways
		req.RequestURI = ""         // Cannot be set in client requests

		// Remove hop-by-hop headers and potentially conflicting headers
		req.Header.Del("Connection")
		req.Header.Del("Keep-Alive")
		req.Header.Del("Accept-Encoding") // Prevent proxy from decompressing automatically if we want raw

		log.Printf("[REPLAY] Firing %s %s to Canary...", req.Method, req.URL.String())

		// 4. Execute the network call
		resp, err := r.client.Do(req)
		elapsed := time.Since(start)

		var canaryBody []byte
		var canaryStatus int
		if err == nil {
			// Drain and close the response body immediately so the Connection Pool can recycle the socket
			canaryBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			canaryStatus = resp.StatusCode

			log.Printf("[REPLAY] Canary replied with %s %d (took %v). Body payload %d bytes", 
				resp.Proto, resp.StatusCode, elapsed, len(canaryBody))
		} else {
			log.Printf("[REPLAY] Failed to contact Canary: %v", err)
		}

		if onDone != nil {
			onDone(CanaryResult{
				Status:  canaryStatus,
				Payload: canaryBody,
				Latency: elapsed,
				Error:   err,
			})
		}
	}()
}
