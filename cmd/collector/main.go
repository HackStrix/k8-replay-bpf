package main

import (
	"log"

	"github.com/hackstrix/k8-replay-bpf/collector"
)

func main() {
	log.Println("Starting Collector...")
	srv := collector.NewServer("0.0.0.0:9000")
	if err := srv.Start(); err != nil {
		log.Fatalf("Collector server failed: %v", err)
	}
}
