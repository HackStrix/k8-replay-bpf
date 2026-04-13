package main

import edge "github.com/hackstrix/k8-replay-bpf/edge"

func main() {
    // TODO: for now this will setup the kprobe implementation and just run it
    // in the future this should be using cobra to properly 
    // take commands and flags.
    edge.RunEdge()
}