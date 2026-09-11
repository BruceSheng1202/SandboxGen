#!/bin/bash
# linux_start.sh — Start the Linux analysis VM (cuckoo2_linux)

# INF-11 fix: fail on unset variables and unguarded command failures
# instead of silently continuing with a broken VM/agent/snapshot state.
# The `|| true` added below at systemctl-is-active/restart call sites are
# intentional — those checks are meant to detect and warn about a
# not-yet-active state, not to abort the script.
set -euo pipefail

CAPE_CONTAINER="cape"
LINUX_VM="cuckoo2_linux"
LINUX_XML="/work/vms/cuckoo2_linux.xml"
LINUX_IP="192.168.122.106"

# INF-06 fix: no hardcoded guest credential. Set these env vars before
# running this script to enable the automatic SSH agent-restart fallback;
# if unset, that one fallback step is simply skipped (the VM/agent can
# still be brought up manually).
LINUX_VM_USER="${SANDBOXGEN_LINUX_VM_USER:-analyst}"
LINUX_VM_PASSWORD="${SANDBOXGEN_LINUX_VM_PASSWORD:-}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[LIN]${NC} $1"; }
warn() { echo -e "${YELLOW}[LIN]${NC} $1"; }
fail() { echo -e "${RED}[LIN]${NC} $1"; exit 1; }

echo ""
echo "================================================"
echo "  Linux VM Startup (cuckoo2_linux)"
echo "================================================"
echo ""

# ── Step 1: Verify container is running ──────────────────────────────
if ! docker ps --format '{{.Names}}' | grep -q "^${CAPE_CONTAINER}$"; then
    fail "Docker container '$CAPE_CONTAINER' is not running. Run amsa_start.sh first."
fi

# ── Step 2: Start libvirt network ────────────────────────────────────
log "Checking libvirt default network..."
NET_STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh net-info default 2>/dev/null | grep Active | awk '{print \$2}'")
if [ "$NET_STATUS" != "yes" ]; then
    warn "Network not active. Starting..."
    docker exec "$CAPE_CONTAINER" bash -c \
        "virsh net-destroy default 2>/dev/null; sleep 2; virsh net-start default 2>/dev/null"
    sleep 5
fi
log "Libvirt network active."

# ── Step 3: Start Linux VM ───────────────────────────────────────────
log "Checking Linux VM ($LINUX_VM)..."
LINUX_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate $LINUX_VM 2>/dev/null || echo 'not found'")

if echo "$LINUX_STATE" | grep -q "running"; then
    log "Linux VM is already running."
elif echo "$LINUX_STATE" | grep -q "not found"; then
    warn "Linux VM not defined. Re-defining from XML..."
    docker exec "$CAPE_CONTAINER" bash -c "virsh define $LINUX_XML"
    sleep 2
    docker exec "$CAPE_CONTAINER" bash -c "virsh start $LINUX_VM"
    log "Linux VM started. Waiting 30s for boot..."
    sleep 30
elif echo "$LINUX_STATE" | grep -q "shut off\|paused"; then
    warn "Linux VM is $LINUX_STATE. Starting..."
    docker exec "$CAPE_CONTAINER" bash -c "virsh start $LINUX_VM"
    log "Linux VM started. Waiting 30s for boot..."
    sleep 30
else
    fail "Unexpected Linux VM state: $LINUX_STATE"
fi

# ── Step 4: Wait for CAPE agent ──────────────────────────────────────
log "Waiting for CAPE agent on Linux VM ($LINUX_IP:8000)..."
AGENT_UP=false
for i in $(seq 1 18); do
    if docker exec "$CAPE_CONTAINER" bash -c "nc -zw3 $LINUX_IP 8000 2>/dev/null"; then
        log "CAPE agent reachable on Linux VM."
        AGENT_UP=true
        break
    fi
    warn "CAPE agent not reachable yet (attempt $i/18). Waiting 10s..."
    # Try SSH start if agent not up after 5 attempts
    if [ "$i" -eq "5" ]; then
        if [ -n "$LINUX_VM_PASSWORD" ]; then
            warn "Trying to start agent via SSH..."
            docker exec "$CAPE_CONTAINER" bash -c \
                "sshpass -p '$LINUX_VM_PASSWORD' ssh -o StrictHostKeyChecking=no ${LINUX_VM_USER}@$LINUX_IP \
                'nohup python3 /home/${LINUX_VM_USER}/agent.py > /tmp/cape_agent.log 2>&1 &' 2>/dev/null || true"
        else
            warn "SANDBOXGEN_LINUX_VM_PASSWORD not set — skipping automatic SSH agent restart."
        fi
    fi
    sleep 10
done

if [ "$AGENT_UP" = false ]; then
    warn "CAPE agent not reachable after 3 minutes."
    warn "SSH into VM: ssh ${LINUX_VM_USER}@$LINUX_IP (set SANDBOXGEN_LINUX_VM_PASSWORD to enable automatic agent restart)"
    warn "Start agent: python3 /home/${LINUX_VM_USER}/agent.py &"
fi

# ── Step 5: Create snapshot if missing ───────────────────────────────
# INF-08 fix: use "agent_ready" (not "clean_snapshot") so the name matches
# both windows_start.sh and what Executor expects when it reverts VMs.
SNAP_EXISTS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh snapshot-list $LINUX_VM 2>/dev/null | grep agent_ready | wc -l")

if [ "$SNAP_EXISTS" -gt "0" ]; then
    log "Snapshot 'agent_ready' exists."
else
    if [ "$AGENT_UP" = true ]; then
        log "Creating agent_ready snapshot..."
        docker exec "$CAPE_CONTAINER" bash -c \
            "virsh snapshot-create-as $LINUX_VM agent_ready \
            'Clean Linux snapshot with agent' 2>&1"
        log "Snapshot created."
    else
        warn "Agent not up — cannot create snapshot. Start agent manually then run:"
        warn "  docker exec cape virsh snapshot-create-as $LINUX_VM agent_ready 'Clean Linux'"
    fi
fi

# ── Step 6: Restart CAPEv2 services ──────────────────────────────────
log "Restarting CAPEv2 services..."
docker exec "$CAPE_CONTAINER" bash -c \
    "systemctl restart cape.service cape-web.service cape-processor.service" || true
sleep 10

for SVC in cape.service cape-web.service cape-processor.service; do
    STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
        "systemctl is-active $SVC 2>/dev/null" || true)
    if [ "$STATUS" = "active" ]; then
        log "$SVC is running."
    else
        warn "$SVC failed — check: docker exec cape journalctl -u $SVC -n 5"
        # Check if it's a snapshot issue
        docker exec "$CAPE_CONTAINER" bash -c \
            "journalctl -u $SVC -n 3 --no-pager 2>&1 | grep -i 'snapshot\|domain'" || true
    fi
done

# ── Step 7: Final status ──────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Linux VM Status"
echo "================================================"
LINUX_FINAL=$(docker exec "$CAPE_CONTAINER" bash -c "virsh domstate $LINUX_VM 2>/dev/null || echo 'not found'")
AGENT_STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "nc -zw3 $LINUX_IP 8000 2>/dev/null && echo reachable || echo unreachable")
SNAP_COUNT=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh snapshot-list $LINUX_VM 2>/dev/null | grep agent_ready | wc -l")

echo "  Linux VM ($LINUX_VM)      : $LINUX_FINAL"
echo "  CAPE agent ($LINUX_IP:8000) : $AGENT_STATUS"
echo "  Snapshot agent_ready       : $([ "$SNAP_COUNT" -gt 0 ] && echo exists || echo missing)"
echo "  CAPEv2 web interface       : http://10.214.160.197:8001"
echo ""
log "Linux VM startup complete."
