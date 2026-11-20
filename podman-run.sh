#!/usr/bin/env bash
# Build and run n3rve in Podman (Intel Iris Xe / iGPU passthrough).
set -euo pipefail

IMAGE="localhost/n3rve:latest"
CONTAINER="n3rve"

echo "[*] Building container image..."
podman build -t "$IMAGE" -f Containerfile .

# Stop/remove any existing container with the same name
if podman container exists "$CONTAINER" 2>/dev/null; then
    echo "[*] Removing existing container '$CONTAINER'..."
    podman rm -f "$CONTAINER" >/dev/null
fi

echo "[*] Starting container with GPU passthrough..."
podman run -it --rm \
    --name "$CONTAINER" \
    --device /dev/dri \
    --group-add keep-groups \
    --security-opt label=disable \
    -e HANDSHAKE_NO_AUTOINSTALL=1 \
    -e PYTHONUNBUFFERED=1 \
    -v "$PWD/handshakes:/work/handshakes:z" \
    -v "$PWD/cracked_results:/work/cracked_results:z" \
    -v "$PWD/logs:/work/logs:z" \
    -v "$PWD/hc22000_cache:/work/hc22000_cache:z" \
    -v "$PWD/bin:/work/bin:z" \
    -v "$PWD:/work:z" \
    -w /work \
    "$IMAGE" python3 main.py "$@"
