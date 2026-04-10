package main

//go:generate go tool bpf2go -tags linux counter bpf/counter.c 

//go:generate go tool bpf2go -tags linux redirect bpf/redirect.c 


