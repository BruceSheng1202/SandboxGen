#!/bin/bash
# windows_stop.sh — Gracefully stop the Windows analysis VM (cuckoo1)
#
# Usage:
#   ./windows_stop.sh           # graceful ACPI shutdown
#   ./windows_stop.sh --force   # force stop immediately

set -euo pipefail

CAPE_CONTAINER="cape"
WIN_VM="cuckoo1"
FORCE=false

for arg in "$@"; do
    [ "$arg" = "--force" ] && FORCE=true
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[WIN]${NC} $1"; }
warn() { echo -e "${YELLOW}[WIN]${NC} $1"; }

echo ""
echo "================================================"
echo "  Windows VM Shutdown (cuckoo1)"
echo "================================================"
echo ""

if ! docker ps --format '{{.Names}}' | grep -q "^${CAPE_CONTAINER}$"; then
    warn "Container not running. Nothing to stop."
    exit 0
fi

WIN_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate $WIN_VM 2>/dev/null || echo 'not found'")

if ! echo "$WIN_STATE" | grep -q "running"; then
    log "Windows VM is not running (state: $WIN_STATE)."
    exit 0
fi

if [ "$FORCE" = true ]; then
    warn "Force stopping Windows VM..."
    docker exec "$CAPE_CONTAINER" bash -c "virsh destroy $WIN_VM 2>/dev/null || true"
    log "Windows VM force stopped."
else
    log "Sending graceful shutdown to Windows VM..."
    docker exec "$CAPE_CONTAINER" bash -c "virsh shutdown $WIN_VM 2>/dev/null || true"

    for i in $(seq 1 6); do
        sleep 5
        WIN_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
            "virsh domstate $WIN_VM 2>/dev/null || echo 'not found'")
        if ! echo "$WIN_STATE" | grep -q "running"; then
            log "Windows VM shut down cleanly."
            break
        fi
        warn "Still shutting down... (${i}0s elapsed)"
    done

    # Force if still running after 30s
    WIN_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
        "virsh domstate $WIN_VM 2>/dev/null || echo 'not found'")
    if echo "$WIN_STATE" | grep -q "running"; then
        warn "Graceful shutdown timed out. Forcing stop..."
        docker exec "$CAPE_CONTAINER" bash -c "virsh destroy $WIN_VM 2>/dev/null || true"
        log "Windows VM force stopped."
    fi
fi

echo ""
echo "================================================"
WIN_FINAL=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate $WIN_VM 2>/dev/null || echo stopped")
echo "  Windows VM ($WIN_VM) : $WIN_FINAL"
echo "================================================"
log "Windows VM stopped. To restart: ./windows_start.sh"
