#!/usr/bin/env bash
# =============================================================================
# build_guest.sh — build the SandboxGEN Linux golden image (qemu backend)
#
# Runs entirely rootless: qemu (TCG) inside a podman container. Produces
#   $VM_DIR/golden.qcow2   Ubuntu 24.04 minimal + strace/tcpdump + in-guest
#                          agent, with an internal snapshot "agent_ready"
#                          taken while the agent is up, so analysis runs
#                          may use this snapshot for diagnostics. The current
#                          Linux runner boots a fresh overlay instead.
#
# This is the ONLY time the guest has network (apt). Analysis runs use
# -netdev user,restrict=on and are isolated from the host and the outside.
#
# Usage: build_guest.sh [VM_DIR]    (default /scratch/$USER/sandboxgen-vm)
# Needs: $VM_DIR/noble-minimal.img (ubuntu-24.04-minimal-cloudimg-amd64.img)
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="${1:-/scratch/$USER/sandboxgen-vm}"
IMAGE="${SANDBOXGEN_QEMU_IMAGE:-localhost/sandboxgen-qemu:alpine3.20}"
BASE="$VM_DIR/noble-minimal.img"
GOLDEN="$VM_DIR/golden.qcow2"
LOG="$VM_DIR/build.log"
DISK_GB="${DISK_GB:-8}"
MEM_MB="${MEM_MB:-1536}"
SMP="${SMP:-4}"

[[ -f "$BASE" ]] || { echo "base image missing: $BASE" >&2; exit 1; }
podman image exists "$IMAGE" || podman build -q -t "$IMAGE" "$HERE"

# --- cloud-init seed (NoCloud, ISO9660 volume label "cidata") -----------------
AGENT_B64=$(base64 -w0 "$HERE/guest/agent.py")
sed "s|@AGENT_B64@|$AGENT_B64|" "$HERE/guest/user-data" > "$VM_DIR/user-data"
cp "$HERE/guest/meta-data" "$VM_DIR/meta-data"
podman run --rm -v "$VM_DIR:/images:rw" "$IMAGE" sh -c "
  cd /images && rm -f seed.iso &&
  xorriso -as mkisofs -quiet -o seed.iso -V cidata -J -r user-data meta-data"

# --- fresh golden disk: standalone copy of the base, grown to $DISK_GB --------
podman run --rm -v "$VM_DIR:/images:rw" "$IMAGE" sh -c "
  cd /images && rm -f golden.qcow2 &&
  qemu-img convert -O qcow2 noble-minimal.img golden.qcow2 &&
  qemu-img resize golden.qcow2 ${DISK_GB}G"

# --- boot once with network, wait for the agent, snapshot, quit ---------------
cat > "$VM_DIR/build_driver.py" <<'PY'
import json, os, socket, subprocess, sys, time, urllib.request
MEM, SMP = os.environ["MEM_MB"], os.environ["SMP"]
mon = "/tmp/mon.sock"
cmd = ["qemu-system-x86_64", "-accel", "tcg,thread=multi", "-m", MEM, "-smp", SMP,
       "-cpu", "max", "-nographic", "-display", "none",
       "-drive", "file=/images/golden.qcow2,if=virtio,format=qcow2",
       "-drive", "file=/images/seed.iso,if=virtio,format=raw,readonly=on",
       "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:18000-:8000",
       "-device", "virtio-net-pci,netdev=n0",
       "-device", "virtio-rng-pci",
       "-monitor", f"unix:{mon},server,nowait",
       "-serial", "file:/images/build-serial.log"]
print("qemu:", " ".join(cmd), flush=True)
p = subprocess.Popen(cmd)
deadline = time.time() + int(os.environ.get("BOOT_TIMEOUT", "1800"))
ready = False
while time.time() < deadline and p.poll() is None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:18000/status", timeout=3) as r:
            st = json.load(r)
            if st.get("status") == "ready":
                ready = True
                print("agent ready:", st, flush=True)
                break
    except Exception:
        pass
    time.sleep(5)
if not ready:
    p.kill(); print("agent never came up", flush=True); sys.exit(2)
time.sleep(20)          # let cloud-init finish its final module
def hmp(line):
    s = socket.socket(socket.AF_UNIX); s.connect(mon); time.sleep(0.5); s.recv(65536)
    s.sendall((line + "\n").encode()); time.sleep(1)
    out = b""
    s.settimeout(120)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            out += chunk
            if b"(qemu)" in out[-32:]: break
    except socket.timeout:
        pass
    s.close(); return out.decode(errors="replace")
print(hmp("savevm agent_ready"), flush=True)
print(hmp("info snapshots"), flush=True)
hmp("quit")
try:
    p.wait(timeout=120)
except subprocess.TimeoutExpired:
    p.kill()
print("golden image built", flush=True)
PY
podman run --rm --name sandboxgen-build -v "$VM_DIR:/images:rw" \
    -e MEM_MB="$MEM_MB" -e SMP="$SMP" -e BOOT_TIMEOUT="${BOOT_TIMEOUT:-1800}" \
    --memory 6g --pids-limit 512 "$IMAGE" \
    python3 /images/build_driver.py 2>&1 | tee "$LOG"

podman run --rm -v "$VM_DIR:/images:ro" "$IMAGE" qemu-img info /images/golden.qcow2 | tee -a "$LOG"
echo "golden image: $GOLDEN"
