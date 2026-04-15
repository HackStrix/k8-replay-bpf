k8s_yaml('k8s/daemonset.yaml')

# Instruct tilt to push to the local k3d registry instead of Docker Hub
default_registry('localhost:5000')

local_resource(
    'compile-ebpf-go',
    cmd='make build',
    deps=['cmd', 'pkg', 'edge']
)

docker_build(
    'ebpf-repeater',
    '.',
    live_update=[
        sync('./bin/mirroring', '/app/mirroring'),
        run('kill -TERM $(pidof mirroring) || true; while pidof mirroring > /dev/null; do sleep 0.1; done; /app/mirroring &')
    ]
)
