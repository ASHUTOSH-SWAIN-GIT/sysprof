#!/usr/bin/env bash
# Runs sysprof with real eBPF data inside Docker's Linux VM, with a small
# workload generating varied syscalls. Shield, bypass and scheduler panels run
# against the VM kernel too (try Simulate attack, Run benchmark, Inject load). Open http://127.0.0.1:8080 afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -m)" in
  arm64|aarch64) GOARCH=arm64 ;;
  *)             GOARCH=amd64 ;;
esac

echo ">> building linux/$GOARCH binary"
GOOS=linux GOARCH=$GOARCH go build -o bin/sysprof-linux ./cmd/sysprof

echo ">> starting container (Ctrl+C to stop), UI on http://127.0.0.1:8080"
# --privileged: needed for bpf() and tracefs.
# --pid=host:   see processes of the whole Docker VM, not just the container.
docker run --rm -it --init --privileged --pid=host \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/bin":/s:ro \
  debian:stable-slim bash -c '
    mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true

    # Workload: disk writes + fsync, directory walking, sleeping.
    ( while :; do
        dd if=/dev/zero of=/tmp/sysprof.bin bs=4k count=20000 conv=fsync status=none
        find /usr /etc -xdev >/dev/null 2>&1
        sleep 0.2
      done ) &

    # The port is only published on 127.0.0.1 of the host, so remote control
    # from inside the container network is safe here.
    exec /s/sysprof-linux serve --addr 0.0.0.0:8080 --unsafe-remote-control
  '
