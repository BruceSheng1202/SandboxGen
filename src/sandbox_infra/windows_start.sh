#!/bin/bash
# windows_start.sh — Start the Windows analysis VM (cuckoo1) and CAPEv2 services
#
# Usage:
#   ./windows_start.sh

# INF-11 fix: fail on unset variables and unguarded command failures
# instead of silently continuing with a broken VM/agent/snapshot state.
# The `|| true` added below at systemctl-is-active/restart and
# virsh-start-retry call sites are intentional — those are meant to
# detect a not-yet-ready state and retry/warn, not to abort the script.
set -euo pipefail

CAPE_CONTAINER="cape"
WIN_VM="cuckoo1"
WIN_IP="192.168.122.105"
WIN_XML="/work/vms/cuckoo1.xml"
VENV="${CAPE_VENV:?Set CAPE_VENV to the virtualenv path inside the CAPEv2 container}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[WIN]${NC} $1"; }
warn() { echo -e "${YELLOW}[WIN]${NC} $1"; }
fail() { echo -e "${RED}[WIN]${NC} $1"; exit 1; }

echo ""
echo "================================================"
echo "  Windows VM Startup (cuckoo1)"
echo "================================================"
echo ""

# ── Step 1: Verify container is running ──────────────────────────────
if ! docker ps --format '{{.Names}}' | grep -q "^${CAPE_CONTAINER}$"; then
    fail "Docker container '$CAPE_CONTAINER' is not running. Run amsa_start.sh first."
fi

# ── Step 2: Install libvirt-python in cape user virtualenv ───────────
log "Ensuring libvirt-python is installed..."
docker exec "$CAPE_CONTAINER" bash -c \
    "$VENV/bin/pip install libvirt-python==8.0.0 -q 2>&1 | tail -1"
log "libvirt-python ready."

# ── Step 3: Fix virbr0 conflict ──────────────────────────────────────
log "Cleaning up network bridge..."
docker exec "$CAPE_CONTAINER" bash -c \
    "ip link set virbr0 down 2>/dev/null; \
     ip link delete virbr0 2>/dev/null; \
     ip link delete virbr0-nic 2>/dev/null" 2>/dev/null || true
sleep 2

# ── Step 4: Start libvirt network ────────────────────────────────────
log "Starting libvirt default network..."
docker exec "$CAPE_CONTAINER" bash -c "virsh net-destroy default 2>/dev/null || true"
sleep 2
docker exec "$CAPE_CONTAINER" bash -c "virsh net-start default 2>/dev/null || true"
docker exec "$CAPE_CONTAINER" bash -c "virsh net-autostart default 2>/dev/null || true"
sleep 5

# Wait for network to become active
for i in $(seq 1 10); do
    NET_STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
        "virsh net-info default 2>/dev/null | grep Active | awk '{print \$2}'")
    if [ "$NET_STATUS" = "yes" ]; then
        log "Libvirt network active."
        break
    fi
    warn "Network not active yet (attempt $i/10). Waiting 5s..."
    sleep 5
done

NET_STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh net-info default 2>/dev/null | grep Active | awk '{print \$2}'")
if [ "$NET_STATUS" != "yes" ]; then
    fail "Libvirt network failed to start. Cannot proceed."
fi

# ── Step 5: Start Windows VM ─────────────────────────────────────────
log "Checking Windows VM ($WIN_VM)..."
WIN_STATE=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate $WIN_VM 2>/dev/null || echo 'not found'")

start_vm_with_retry() {
    for attempt in 1 2 3; do
        START_OUT=$(docker exec "$CAPE_CONTAINER" bash -c "virsh start $WIN_VM 2>&1" || true)
        if echo "$START_OUT" | grep -q "started"; then
            log "Windows VM started. Waiting 30s for boot..."
            sleep 30
            return 0
        else
            warn "Start failed (attempt $attempt/3): $START_OUT"
            warn "Restarting network and retrying..."
            docker exec "$CAPE_CONTAINER" bash -c \
                "virsh net-destroy default 2>/dev/null; sleep 3; virsh net-start default 2>/dev/null" || true
            sleep 5
        fi
    done
    fail "Could not start Windows VM after 3 attempts."
}

if echo "$WIN_STATE" | grep -q "running"; then
    log "Windows VM is already running."
elif echo "$WIN_STATE" | grep -q "not found"; then
    warn "Windows VM not defined. Re-defining from XML..."
    docker exec "$CAPE_CONTAINER" bash -c "virsh define $WIN_XML 2>&1"
    sleep 3
    start_vm_with_retry
elif echo "$WIN_STATE" | grep -q "shut off\|paused"; then
    warn "Windows VM is $WIN_STATE. Starting..."
    start_vm_with_retry
else
    fail "Unexpected Windows VM state: $WIN_STATE"
fi

# ── Step 6: Check for existing snapshot ──────────────────────────────
SNAP_EXISTS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh snapshot-list $WIN_VM 2>/dev/null | grep agent_ready | wc -l")
if [ "$SNAP_EXISTS" -gt "0" ]; then
    log "Snapshot 'agent_ready' exists."
else
    warn "Snapshot 'agent_ready' not found — will create after agent comes up."
fi

# ── Step 7: Wait for CAPE agent ──────────────────────────────────────
log "Checking CAPE agent on Windows VM ($WIN_IP:8000)..."
AGENT_UP=false
for i in $(seq 1 18); do
    if docker exec "$CAPE_CONTAINER" bash -c "nc -zw3 $WIN_IP 8000 2>/dev/null"; then
        log "CAPE agent reachable on Windows VM."
        AGENT_UP=true
        break
    fi
    warn "CAPE agent not reachable yet (attempt $i/18). Waiting 10s..."
    sleep 10
done

if [ "$AGENT_UP" = false ]; then
    warn "CAPE agent not reachable after 3 minutes."
    warn "Windows may still be booting. Check VNC at 10.214.160.197:5900"
    warn "Manually run: python C:\\agent.py in Windows"
fi

# ── Step 8: Disable Windows Defender via agent (BEFORE the golden ────
# snapshot is taken — INF-09 fix: a snapshot taken while Defender is
# still active would re-enable Defender on every revert-to-snapshot).
DEFENDER_OK=false
if [ "$AGENT_UP" = true ]; then
    log "Disabling Windows Defender..."
    DEFENDER_RESULT=$(python3 -c "
import requests, sys
try:
    r = requests.post('http://$WIN_IP:8000/execute',
        data={'command': 'powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring \$true; Set-MpPreference -DisableIOAVProtection \$true; Set-MpPreference -DisableBehaviorMonitoring \$true; Set-MpPreference -DisableBlockAtFirstSeen \$true; Set-MpPreference -DisableScriptScanning \$true\"'},
        timeout=20)
    print('OK' if r.status_code == 200 else f'HTTP_{r.status_code}')
except Exception as e:
    print(f'ERROR:{e}')
" 2>/dev/null)
    if [ "$DEFENDER_RESULT" = "OK" ]; then
        log "Defender disabled and confirmed (HTTP 200)."
        DEFENDER_OK=true
    else
        warn "Defender disable did not confirm success: $DEFENDER_RESULT"
    fi
fi

# ── Step 9: Create snapshot if missing and agent is up ───────────────
if [ "$AGENT_UP" = true ] && [ "$SNAP_EXISTS" -eq "0" ]; then
    if [ "$DEFENDER_OK" != true ]; then
        fail "Refusing to create the 'agent_ready' golden snapshot: Windows Defender disable was not confirmed successful. Taking the snapshot now would re-enable Defender on every future revert-to-snapshot (INF-09). Fix agent connectivity and re-run."
    fi
    log "Creating agent_ready snapshot..."
    docker exec "$CAPE_CONTAINER" bash -c \
        "virsh snapshot-create-as $WIN_VM agent_ready \
        'Clean snapshot with CAPE agent running' 2>&1"
    log "Snapshot created."
fi

# ── Step 10: Start CAPEv2 services ───────────────────────────────────
log "Starting CAPEv2 services..."
docker exec "$CAPE_CONTAINER" bash -c \
    "systemctl restart cape.service cape-web.service cape-processor.service" || true
sleep 10

for SVC in cape.service cape-web.service cape-processor.service; do
    STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
        "systemctl is-active $SVC 2>/dev/null" || true)
    if [ "$STATUS" = "active" ]; then
        log "$SVC is running."
    else
        warn "$SVC failed — check: docker exec cape journalctl -u $SVC -n 10"
    fi
done

# ── Step 11: Final status ─────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Windows VM Status"
echo "================================================"
WIN_FINAL=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh domstate $WIN_VM 2>/dev/null || echo 'not found'")
AGENT_STATUS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "nc -zw3 $WIN_IP 8000 2>/dev/null && echo reachable || echo unreachable")
SNAP_COUNT=$(docker exec "$CAPE_CONTAINER" bash -c \
    "virsh snapshot-list $WIN_VM 2>/dev/null | grep agent_ready | wc -l")

echo "  Windows VM ($WIN_VM)       : $WIN_FINAL"
echo "  CAPE agent ($WIN_IP:8000)  : $AGENT_STATUS"
echo "  Snapshot agent_ready       : $([ "$SNAP_COUNT" -gt 0 ] && echo exists || echo missing)"
echo "  CAPEv2 web interface       : http://10.214.160.197:8001"
echo ""
log "Windows VM startup complete."
