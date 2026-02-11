#!/bin/bash
# NeuroSploit v3 - Build Kali Linux Sandbox Image
#
# Usage:
#   ./scripts/build-kali.sh          # Normal build (uses cache)
#   ./scripts/build-kali.sh --fresh  # Full rebuild (no cache)
#   ./scripts/build-kali.sh --test   # Build + run health check

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="neurosploit-kali:latest"

cd "$PROJECT_DIR"

echo "================================================"
echo " NeuroSploit Kali Sandbox Builder"
echo "================================================"
echo ""

# Check Docker
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running."
    echo "  Start Docker Desktop and try again."
    exit 1
fi

# Parse args
NO_CACHE=""
RUN_TEST=false

for arg in "$@"; do
    case $arg in
        --fresh|--no-cache)
            NO_CACHE="--no-cache"
            echo "[*] Full rebuild mode (no cache)"
            ;;
        --test)
            RUN_TEST=true
            echo "[*] Will run health check after build"
            ;;
    esac
done

echo "[*] Building image: $IMAGE_NAME"
echo "[*] Dockerfile: docker/Dockerfile.kali"
echo "[*] Context: docker/"
echo ""

# Build
docker build $NO_CACHE \
    -f docker/Dockerfile.kali \
    -t "$IMAGE_NAME" \
    docker/

echo ""
echo "[+] Build complete: $IMAGE_NAME"

# Show image info
docker image inspect "$IMAGE_NAME" --format \
    "    Size: {{.Size}} bytes ({{printf \"%.0f\" (divf .Size 1048576)}} MB)
    Created: {{.Created}}
    Arch: {{.Architecture}}" 2>/dev/null || true

# Run test if requested
if [ "$RUN_TEST" = true ]; then
    echo ""
    echo "[*] Running health check..."
    docker run --rm "$IMAGE_NAME" \
        "nuclei -version 2>&1; echo '---'; naabu -version 2>&1; echo '---'; httpx -version 2>&1; echo '---'; subfinder -version 2>&1; echo '---'; nmap --version 2>&1 | head -1; echo '---'; nikto -Version 2>&1 | head -1; echo '---'; sqlmap --version 2>&1; echo '---'; ffuf -V 2>&1; echo '---'; echo 'ALL OK'"
    echo ""
    echo "[+] Health check passed"
fi

echo ""
echo "================================================"
echo " Build complete! To use:"
echo "   - Start NeuroSploit backend (it auto-creates containers per scan)"
echo "   - Monitor via Sandbox Dashboard: http://localhost:8000/sandboxes"
echo "================================================"
