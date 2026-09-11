#!/bin/bash
# amsa_stop.sh — Gracefully shut down the full AMSA + CAPEv2 stack
#
# Stops services in the correct order:
#   1. CAPEv2 services (stop accepting new tasks)
#   2. Windows VM (graceful shutdown)
#   3. Linux VM (graceful shutdown)
#   4. Docker container (optional — pass --container to also stop it)
#
# Usage:
#   ./amsa_stop.sh              # stop services and VMs, keep container running
#   ./amsa_stop.sh --container  # also stop the Docker container
#   ./amsa_stop.sh --full       # stop everything including container

set -euo pipefail

CAPE_CONTAINER="cape"
STOP_CONTAINER=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --container|--full)
            STOP_CONTAINER=true
            ;;
    esac
done

# Colours
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[AMSA]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo ""
echo "================================================"
echo "  AMSA + CAPEv2 Shutdown"
echo "================================================"
echo ""

# Check container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CAPE_CONTAINER}$"; then
    warn "Container '$CAPE_CONTAINER' is not running. Nothing to stop."
    exit 0
fi

# ── Step 1: Stop accepting new tasks (web service only) ───────────────
# INF-10 fix: previously stopped cape-processor.service (which is what's
# actually running analyses) *before* checking for running tasks, and
# queried the wrong port (8000 — the pre-INF-06/amsa_start.sh port move
# to 8001). Correct order: block new submissions first by stopping only
# the web frontend, then wait for whatever the processor is already
# running to finish, then stop the processor/core services.
log "Stopping cape-web service (blocks new submissions)..."
WEB_STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "systemctl is-active cape-web.service 2>/dev/null || echo inactive")
if [ "$WEB_STATUS" = "active" ]; then
    docker exec "$CAPE_CONTAINER" bash -c "systemctl stop cape-web.service"
    log "cape-web.service stopped — no new submissions can be accepted."
else
    log "cape-web.service was already inactive."
fi

# ── Step 2: Wait for any running analysis to complete ─────────────────
log "Checking for running analysis tasks..."
RUNNING=$(curl -s http://localhost:8001/apiv2/tasks/list/ 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tasks = data.get('data', {}).get('tasks', [])
    running = [t for t in tasks if t.get('status') == 'running']
    print(len(running))
except:
    print(0)
" 2>/dev/null || echo "0")

if [ "$RUNNING" -gt "0" ] 2>/dev/null; then
    warn "$RUNNING analysis task(s) still running. Waiting up to 60s..."
    for i in $(seq 1 12); do
        sleep 5
        RUNNING=$(curl -s http://localhost:8001/apiv2/tasks/list/ 2>/dev/null \
            | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tasks = data.get('data', {}).get('tasks', [])
    running = [t for t in tasks if t.get('status') == 'running']
    print(len(running))
except:
    print(0)
" 2>/dev/null || echo "0")
        if [ "$RUNNING" = "0" ]; then
            log "All tasks completed."
            break
        fi
        warn "Still waiting... ($RUNNING running, ${i}0s elapsed)"
    done
    if [ "$RUNNING" -gt "0" ] 2>/dev/null; then
        warn "Tasks still running after 60s — proceeding with shutdown anyway."
    fi
else
    log "No running analysis tasks."
fi

# ── Step 2b: Stop remaining CAPEv2 services ────────────────────────────
log "Stopping remaining CAPEv2 services..."
for SERVICE in cape.service cape-processor.service; do
    STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
        "systemctl is-active $SERVICE 2>/dev/null || echo inactive")
    if [ "$STATUS" = "active" ]; then
        log "Stopping $SERVICE..."
        docker exec "$CAPE_CONTAINER" bash -c "systemctl stop $SERVICE"
        log "$SERVICE stopped."
    else
        log "$SERVICE was already inactive."
    fi
done

# ── Step 3: Gracefully shut down Windows VM ───────────────────────────
log "Shutting down Windows VM (cuckoo1)..."
WIN_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate cuckoo1 2>/dev/null || echo 'not found'")

if echo "$WIN_STATE" | grep -q "running"; then
    # Try graceful ACPI shutdown first
    docker exec "$CAPE_CONTAINER" bash -c \
        "virsh shutdown cuckoo1 2>/dev/null || true"
    log "Sent shutdown signal to Windows VM. Waiting up to 30s..."

    for i in $(seq 1 6); do
        sleep 5
        WIN_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
            "virsh domstate cuckoo1 2>/dev/null || echo 'not found'")
        if ! echo "$WIN_STATE" | grep -q "running"; then
            log "Windows VM shut down cleanly."
            break
        fi
        warn "Still shutting down... (${i}0s elapsed)"
    done

    # Force stop if still running
    WIN_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
        "virsh domstate cuckoo1 2>/dev/null || echo 'not found'")
    if echo "$WIN_STATE" | grep -q "running"; then
        warn "Windows VM did not shut down cleanly. Forcing stop..."
        docker exec "$CAPE_CONTAINER" bash -c "virsh destroy cuckoo1 2>/dev/null || true"
        log "Windows VM force stopped."
    fi
else
    log "Windows VM was not running (state: $WIN_STATE)."
fi

# ── Step 4: Gracefully shut down Linux VM (if configured) ─────────────
log "Checking Linux VM (cuckoo2_linux)..."
LINUX_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate cuckoo2_linux 2>/dev/null || echo 'not found'")

if echo "$LINUX_STATE" | grep -q "running"; then
    log "Shutting down Linux VM (cuckoo2_linux)..."
    docker exec "$CAPE_CONTAINER" bash -c \
        "virsh shutdown cuckoo2_linux 2>/dev/null || true"
    sleep 10

    LINUX_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
        "virsh domstate cuckoo2_linux 2>/dev/null || echo 'not found'")
    if echo "$LINUX_STATE" | grep -q "running"; then
        warn "Linux VM did not shut down cleanly. Forcing stop..."
        docker exec "$CAPE_CONTAINER" bash -c \
            "virsh destroy cuckoo2_linux 2>/dev/null || true"
    else
        log "Linux VM shut down cleanly."
    fi
elif echo "$LINUX_STATE" | grep -q "not found"; then
    log "Linux VM not configured — skipping."
else
    log "Linux VM was not running (state: $LINUX_STATE)."
fi

# ── Step 5: Stop Docker container (optional) ──────────────────────────
if [ "$STOP_CONTAINER" = true ]; then
    log "Stopping Docker container '$CAPE_CONTAINER'..."
    docker stop "$CAPE_CONTAINER"
    log "Container stopped."
else
    log "Docker container left running (use --container to stop it)."
fi

echo ""
echo "================================================"
echo "  Shutdown Complete"
echo "================================================"
echo ""
echo "  CAPEv2 services : stopped"
WIN_FINAL=$(docker exec "$CAPE_CONTAINER" bash -c \
    'virsh domstate cuckoo1 2>/dev/null || echo "stopped"' 2>/dev/null || echo "container stopped")
echo "  Windows VM      : $WIN_FINAL"
if [ "$STOP_CONTAINER" = true ]; then
    echo "  Docker container: stopped"
else
    echo "  Docker container: still running (restart with: ./amsa_start.sh)"
fi
echo ""
log "To restart: ./amsa_start.sh"
