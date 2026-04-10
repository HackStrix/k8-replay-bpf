package ebpf

//go:generate go tool bpf2go -tags linux  -output-dir bytecode Counter bpf/counter.c 

//go:generate go tool bpf2go -tags linux  -output-dir bytecode Redirect bpf/redirect.c 
