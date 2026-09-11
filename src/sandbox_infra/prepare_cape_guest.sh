#!/bin/bash
# prepare_cape_guest.sh
# Run once on the host to prepare the CAPE Windows guest VM before snapshotting.
# Connects via VNC-accessible console using virsh send-key, or via SSH if available.
#
# Usage: ./prepare_cape_guest.sh [vm-name]
#   Default VM name: cuckoo1

# INF-11 fix: fail on unset variables and unguarded command failures.
# `|| true` is added below at every curl/virsh probe that this interactive
# tool already treats as a soft "not reachable yet, warn and continue"
# signal rather than a hard stop.
set -euo pipefail

VM="${1:-cuckoo1}"
GUEST_IP="192.168.122.105"
AGENT_PORT="8000"

echo "[*] CAPE Guest Preparation Script"
echo "[*] Target VM: $VM ($GUEST_IP)"
echo ""

# ── Step 1: Check VM is running ──────────────────────────────────────────────
echo "[1] Checking VM state..."
STATE=$(virsh domstate "$VM" 2>/dev/null || true)
if [[ "$STATE" != "running" ]]; then
    echo "    VM not running (state: $STATE). Starting..."
    virsh start "$VM"
    echo "    Waiting 30s for boot..."
    sleep 30
else
    echo "    VM is running."
fi

# ── Step 2: Check agent is reachable ─────────────────────────────────────────
echo ""
echo "[2] Checking CAPE agent reachability..."
AGENT_STATUS=$(curl -s --max-time 5 "http://$GUEST_IP:$AGENT_PORT/" 2>/dev/null || true)
if echo "$AGENT_STATUS" | grep -q "CAPE"; then
    echo "    Agent is reachable."
else
    echo "    WARNING: Agent not responding at http://$GUEST_IP:$AGENT_PORT/"
    echo "    Continue anyway? (y/N)"
    read -r resp
    [[ "$resp" != "y" ]] && exit 1
fi

# ── Step 3: Upload the Defender disable script ───────────────────────────────
echo ""
echo "[3] Uploading Defender disable script to guest..."

PS_SCRIPT='reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScriptScanning /t REG_DWORD /d 1 /f
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
Stop-Service WinDefend -Force -ErrorAction SilentlyContinue
Set-Service WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "Defender disabled."'

# Upload via CAPE agent file upload endpoint
UPLOAD_RESULT=$(curl -s --max-time 10 \
    -X POST "http://$GUEST_IP:$AGENT_PORT/store" \
    -F "filepath=C:\\disable_defender.ps1" \
    -F "data=@-;filename=disable_defender.ps1" \
    <<< "$PS_SCRIPT" 2>/dev/null || true)

echo "    Upload result: $UPLOAD_RESULT"

# ── Step 4: Execute via elevated process ─────────────────────────────────────
# The agent runs as a limited user — we use a scheduled task to run elevated
echo ""
echo "[4] Creating elevated scheduled task to run Defender disable..."

SCHTASK_CMD='schtasks /create /tn "DisableDefender" /tr "powershell -ExecutionPolicy Bypass -File C:\\disable_defender.ps1" /sc once /st 00:00 /ru SYSTEM /f'

curl -s --max-time 10 \
    -X POST "http://$GUEST_IP:$AGENT_PORT/execute" \
    --data-urlencode "command=cmd /c $SCHTASK_CMD" > /tmp/schtask_create.json 2>/dev/null || true
echo "    $(cat /tmp/schtask_create.json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("message",""))' 2>/dev/null || true)"

sleep 2

echo "[5] Running the scheduled task as SYSTEM..."
curl -s --max-time 15 \
    -X POST "http://$GUEST_IP:$AGENT_PORT/execute" \
    --data-urlencode 'command=cmd /c schtasks /run /tn "DisableDefender"' > /tmp/schtask_run.json 2>/dev/null || true
echo "    $(cat /tmp/schtask_run.json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("message",""))' 2>/dev/null || true)"

sleep 10

# ── Step 5: Verify ────────────────────────────────────────────────────────────
echo ""
echo "[6] Verifying Defender status..."
VERIFY=$(curl -s --max-time 10 \
    -X POST "http://$GUEST_IP:$AGENT_PORT/execute" \
    --data-urlencode 'command=powershell -Command "Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableIOAVProtection,DisableBehaviorMonitoring"' 2>/dev/null || true)
echo "    $VERIFY" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("stdout",""))' 2>/dev/null || true

# ── Step 6: Snapshot ─────────────────────────────────────────────────────────
echo ""
echo "[7] Ready to snapshot. Take snapshot now? (y/N)"
read -r snap_resp
if [[ "$snap_resp" == "y" ]]; then
    # INF-08 fix: use "agent_ready" so this manual path produces the same
    # snapshot name as linux_start.sh/windows_start.sh and what Executor
    # expects, instead of a third, timestamped naming scheme.
    SNAP_NAME="agent_ready"
    echo "    Taking snapshot: $SNAP_NAME"
    docker exec cape bash -c "virsh snapshot-create-as $VM $SNAP_NAME --disk-only --atomic" 2>/dev/null || \
    virsh snapshot-create-as "$VM" "$SNAP_NAME" --atomic
    echo "    Done. Snapshot: $SNAP_NAME"
    echo ""
    echo "    Update your CAPE config to use this snapshot:"
    echo "    snapshot = $SNAP_NAME"
else
    echo "    Skipping snapshot. Run manually:"
    echo "    virsh snapshot-create-as $VM <snapshot-name> --atomic"
fi

echo ""
echo "[*] Guest preparation complete."
