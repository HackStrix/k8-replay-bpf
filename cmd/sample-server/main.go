package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	version := os.Getenv("VERSION")
	if version == "" {
		version = "unknown"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] Received Request: %s %s from %s", version, r.Method, r.URL.Path, r.RemoteAddr)
		
		// Log headers
		for k, v := range r.Header {
			log.Printf("[%s] Header: %s = %v", version, k, v)
		}

		// Read and log body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[%s] Error reading body: %v", version, err)
		} else if len(body) > 0 {
			log.Printf("[%s] Body: %s", version, string(body))
		}

		fmt.Fprintf(w, "Hello from Sample Server (%s)\n", version)
	})

	log.Printf("Starting Sample Server (%s) on :%s", version, port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
