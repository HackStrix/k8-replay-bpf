k8s_yaml(['k8s/rbac.yaml', 'k8s/sample-server.yaml', 'k8s/collector.yaml', 'k8s/daemonset.yaml'])

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

docker_build(
    'dev-registry:5000/sample-server',
    '.',
    dockerfile='Dockerfile.sample',
    live_update=[
        sync('./bin/sample-server', '/app/sample-server'),
        run('kill -TERM $(pidof sample-server) || true; while pidof sample-server > /dev/null; do sleep 0.1; done; /app/sample-server &')
    ]
)

docker_build(
    'dev-registry:5000/collector',
    '.',
    dockerfile='Dockerfile.collector',
    live_update=[
        sync('./bin/collector', '/app/collector'),
        run('kill -TERM $(pidof collector) || true; while pidof collector > /dev/null; do sleep 0.1; done; /app/collector &')
    ]
)
