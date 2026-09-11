#!/bin/bash
# linux_stop.sh — Gracefully stop the Linux analysis VM (cuckoo2_linux)
#
# Usage:
#   ./linux_stop.sh           # graceful shutdown
#   ./linux_stop.sh --force   # force stop immediately

set -euo pipefail

CAPE_CONTAINER="cape"
LINUX_VM="cuckoo2_linux"
LINUX_IP="192.168.122.106"
FORCE=false

for arg in "$@"; do
    [ "$arg" = "--force" ] && FORCE=true
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[LIN]${NC} $1"; }
warn() { echo -e "${YELLOW}[LIN]${NC} $1"; }

echo ""
echo "================================================"
echo "  Linux VM Shutdown (cuckoo2_linux)"
echo "================================================"
echo ""

if ! docker ps --format '{{.Names}}' | grep -q "^${CAPE_CONTAINER}$"; then
    warn "Container not running. Nothing to stop."
    exit 0
fi

LINUX_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate $LINUX_VM 2>/dev/null || echo 'not found'")

if ! echo "$LINUX_STATE" | grep -q "running"; then
    log "Linux VM is not running (state: $LINUX_STATE)."
    exit 0
fi

# Stop CAPE agent inside VM first
log "Stopping CAPE agent inside Linux VM..."
docker exec "$CAPE_CONTAINER" bash -c \
    "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 analyst@$LINUX_IP \
    'pkill -f agent.py 2>/dev/null || true' 2>/dev/null || true"

if [ "$FORCE" = true ]; then
    warn "Force stopping Linux VM..."
    docker exec "$CAPE_CONTAINER" bash -c "virsh destroy $LINUX_VM 2>/dev/null || true"
    log "Linux VM force stopped."
else
    log "Sending graceful shutdown to Linux VM..."
    docker exec "$CAPE_CONTAINER" bash -c "virsh shutdown $LINUX_VM 2>/dev/null || true"

    for i in $(seq 1 4); do
        sleep 5
        LINUX_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
            "virsh domstate $LINUX_VM 2>/dev/null || echo 'not found'")
        if ! echo "$LINUX_STATE" | grep -q "running"; then
            log "Linux VM shut down cleanly."
            break
        fi
        warn "Still shutting down... (${i}0s elapsed)"
    done

    # Force if still running after 20s
    LINUX_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
        "virsh domstate $LINUX_VM 2>/dev/null || echo 'not found'")
    if echo "$LINUX_STATE" | grep -q "running"; then
        warn "Graceful shutdown timed out. Forcing stop..."
        docker exec "$CAPE_CONTAINER" bash -c "virsh destroy $LINUX_VM 2>/dev/null || true"
        log "Linux VM force stopped."
    fi
fi

echo ""
echo "================================================"
LINUX_FINAL=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate $LINUX_VM 2>/dev/null || echo stopped")
echo "  Linux VM ($LINUX_VM) : $LINUX_FINAL"
echo "================================================"
log "Linux VM stopped. To restart: ./linux_start.sh"
