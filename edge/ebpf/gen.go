package ebpf

//go:generate go tool bpf2go -tags linux  -output-dir bytecode Counter raw-bpf-c-files/counter.c 

//go:generate go tool bpf2go -tags linux  -output-dir bytecode Redirect raw-bpf-c-files/redirect.c 

//go:generate go tool bpf2go -tags linux  -output-dir bytecode Kprobe raw-bpf-c-files/kprobe.c 
