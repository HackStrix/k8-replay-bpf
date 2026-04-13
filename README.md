Go replay -> consume all request from all sockets in user space.
        -> parse through all of them in user space.
        -> send them to the target server.


BPF based approach
        -> Instead of consuming these in the user space
        -> we intercept these essentially right at the kernel level.
        -> currently we are intercepting the tc ingress traffic on a single interface
        -> we wanna basically filter these based on ip and port.
            -> once filtered we wanna send these to the user space
            -> since we are filtering in kernel itself we will only copy packets to user space which are required. For perfomance we are gonna be using the ringbuffer 
                -> ringbuffer is the kernel space circular buffer which is used to communicate the data between the kernel and user space.


The end goal of this approach is to build a first class k8 based traffic mirroring tool, for repeating the traffic from one service to canary service. And then provide a dashboard to view the traffic and the responses from the canary service.

This is inspired by the pixie tool, but with the goal of building a first class k8 based traffic mirroring tool.

