#!/usr/bin/env bash
# =============================================================================
# build_windows_guest.sh — build the SandboxGEN Windows golden (qemu TCG, no KVM)
#
# Fully unattended Windows 10 Enterprise Eval install driven by autounattend.xml,
# then Sysmon + the in-guest agent, then an EXTERNAL RAM savestate so per-task
# analysis resumes in seconds instead of booting Windows (which is many minutes
# under TCG). One-time; ~1-3h under TCG.
#
# Produces in $OUT:  win-golden.qcow2  +  win-state.gz  (RAM savestate)
#
# Usage: build_windows_guest.sh
# Env: ISO   (default /scratch/$USER/win10-eval.iso)
#      OUT   (default vmstore  — persistent NFS; golden survives scratch reclaim)
#      WORK  (default /scratch/$USER/winbuild  — fast local disk for the install)
#      MEM_MB(4096)  SMP(8)  DISK_GB(40)  BOOT_TIMEOUT(10800 = 3h; install measured <1h)  STALL_MIN(30)
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"           # .../qemu/windows
QEMU_DIR="$(cd "$HERE/.." && pwd)"                             # .../qemu
IMAGE="${SANDBOXGEN_QEMU_IMAGE:-localhost/sandboxgen-qemu:alpine3.20}"
ISO="${ISO:-/scratch/$USER/win10-eval.iso}"        # default Win10 (lighter under TCG; covers all benchmark PEs)
OUT="${OUT:-/home/$USER/sandboxgen/vmstore}"
WORK="${WORK:-/scratch/$USER/winbuild}"
MEDIA="${SANDBOXGEN_WIN_MEDIA:-/home/$USER/sandboxgen/vmstore/win-media}"  # Sysmon64.exe, config
MEM_MB="${MEM_MB:-4096}"; SMP="${SMP:-8}"; DISK_GB="${DISK_GB:-40}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-10800}"; STALL_MIN="${STALL_MIN:-30}"

[[ -f "$ISO" ]] || { echo "Windows ISO not found: $ISO" >&2; exit 1; }
podman image exists "$IMAGE" || podman build -q -t "$IMAGE" "$QEMU_DIR" >/dev/null
mkdir -p "$WORK" "$OUT"

# --- assemble the SANDBOXGEN media tree (autounattend at root + payload) -------
STAGE="$WORK/media"; rm -rf "$STAGE"; mkdir -p "$STAGE/sandboxgen"
AUTOUNATTEND="${AUTOUNATTEND:-$HERE/autounattend.win10.xml}"
cp "$AUTOUNATTEND" "$STAGE/autounattend.xml"
cp "$HERE/win-agent.ps1" "$HERE/firstlogon.cmd" "$HERE/autoclick.ps1" "$STAGE/sandboxgen/"
cp "$MEDIA/Sysmon64.exe" "$MEDIA/sysmonconfig.xml" "$STAGE/sandboxgen/"

podman run --rm -v "$WORK:/work:rw" -v "$STAGE:/stage:ro" "$IMAGE" sh -c '
  cd /work && rm -f media.iso &&
  xorriso -as mkisofs -quiet -J -V SANDBOXGEN -o media.iso /stage'

# --- fresh install disk (on fast local scratch) -------------------------------
podman run --rm -v "$WORK:/work:rw" "$IMAGE" \
  qemu-img create -q -f qcow2 /work/win-golden.qcow2 "${DISK_GB}G"

# --- run the unattended install, wait for the in-guest agent, savestate -------
cat > "$WORK/win_build_driver.py" <<'PY'
import json, os, socket, struct, subprocess, sys, time, urllib.request, zlib
MEM, SMP = os.environ["MEM_MB"], os.environ["SMP"]
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "10800"))   # 3h: install measured at <1h
STALL_MIN    = int(os.environ.get("STALL_MIN", "30"))         # disk flat this long = warn
mon, disk, shots = "/work/mon.sock", "/work/win-golden.qcow2", "/work/shots"
os.makedirs(shots, exist_ok=True)
cmd = ["qemu-system-x86_64", "-accel", "tcg,thread=multi", "-m", MEM, "-smp", SMP,
       "-cpu", "Nehalem", "-machine", "pc", "-display", "none", "-vga", "std",
       "-drive", "file=/work/win-golden.qcow2,if=ide,format=qcow2",
       "-drive", "file=/iso/win.iso,media=cdrom,readonly=on",
       "-drive", "file=/work/media.iso,media=cdrom,readonly=on",
       "-boot", "once=d",
       # restrict=on: no guest egress during install. With egress OOBE runs the
       # Autopilot/ZDP check and, when Microsoft endpoints are unreachable (compute
       # nodes), stops on "Something went wrong / OOBEZDP" waiting for a click.
       # Isolated, OOBE skips ZDP. hostfwd (agent probe) is unaffected by restrict.
       "-netdev", "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:18000-:8000",
       "-device", "e1000,netdev=n0,id=nic0",
       # nic1: the ONLY path with egress, on its own subnet, link DOWN except for
       # the activation window after the agent is up (Eval licence needs one
       # online activation or Windows shows "License is expired" + forced reboots).
       # Both NICs must exist at analysis time too (device tree == saved state).
       "-netdev", "user,id=n1,net=10.0.3.0/24,hostfwd=tcp:127.0.0.1:18001-:8000",
       "-device", "e1000,netdev=n1,id=nic1",
       "-monitor", f"unix:{mon},server,nowait",
       "-serial", "file:/work/win-build-serial.log"]
print("qemu:", " ".join(cmd), flush=True)
p = subprocess.Popen(cmd)
T0 = time.time()
def ts(): return time.strftime("%H:%M:%S")

def hmp(line, wait=1, quiet=False):
    """send one HMP command, return its output (empty on failure when quiet)."""
    try:
        s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(mon)
        time.sleep(0.3); s.recv(65536)
        s.sendall((line + "\n").encode()); time.sleep(wait)
        out = b""; s.settimeout(600 if not quiet else 5)
        try:
            while True:
                c = s.recv(65536)
                if not c: break
                out += c
                if b"(qemu)" in out[-16:]: break
        except socket.timeout: pass
        s.close(); return out.decode(errors="replace")
    except Exception as e:
        if not quiet: print("monitor error:", e, flush=True)
        return ""

# "Press any key to boot from CD or DVD..." appears a few seconds in and waits
# ~5s for a key. Tap keys for the first ~45s so the first (and only, boot=once=d)
# CD boot starts Windows setup unattended; later reboots go to the HDD.
def _tap_keys():
    end = time.time() + 45
    while time.time() < end:
        hmp("sendkey ret", wait=0.3, quiet=True); time.sleep(2)
import threading
threading.Thread(target=_tap_keys, daemon=True).start()
for _ in range(20):                       # monitor comes up within a second or two
    if "monerr" not in (hmp("set_link nic1 off", 0.3, quiet=True) or "monerr") : break
    time.sleep(0.5)
hmp("set_link nic1 off", 0.5)

def ppm_to_png(src, dst):
    d = open(src, "rb").read(); parts = []; i = 0
    while len(parts) < 4:
        while d[i:i+1].isspace(): i += 1
        j = i
        while not d[j:j+1].isspace(): j += 1
        parts.append(d[i:j]); i = j
    i += 1; w, h = int(parts[1]), int(parts[2]); px = d[i:]
    raw = b"".join(b"\x00" + px[y*w*3:(y+1)*w*3] for y in range(h))
    def ch(t, b): c = t + b; return struct.pack(">I", len(b)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    png = (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
           + ch(b"IDAT", zlib.compress(raw, 6)) + ch(b"IEND", b""))
    open(dst, "wb").write(png)
    # crude scene fingerprint: mean RGB of the frame (OOBE = saturated blue ~ (0,69,124))
    n = w*h; r = sum(px[0::3]) // n; g = sum(px[1::3]) // n; b = sum(px[2::3]) // n
    return w, h, (r, g, b)

def screenshot(tag):
    ppm = f"{shots}/tmp.ppm"
    hmp(f"screendump {ppm}", wait=2, quiet=True)
    if not os.path.exists(ppm): return None
    try:
        info = ppm_to_png(ppm, f"{shots}/{tag}.png")
        import shutil; shutil.copyfile(f"{shots}/{tag}.png", f"{shots}/latest.png")
        os.remove(ppm); return info
    except Exception as e:
        print("screenshot convert failed:", e, flush=True); return None

def agent_ready():
    try:
        with urllib.request.urlopen("http://127.0.0.1:18000/status", timeout=4) as r:
            return json.load(r).get("status") == "ready"
    except Exception:
        return False

deadline = T0 + BOOT_TIMEOUT
ready = False
last_shot = 0; last_size = 0; last_growth = T0; stall_warned = False
while time.time() < deadline and p.poll() is None:
    if agent_ready():
        ready = True; print(f"{ts()} agent ready after {int((time.time()-T0)/60)} min", flush=True); break
    now = time.time()
    if now - last_shot >= 60:
        last_shot = now
        size = os.path.getsize(disk) if os.path.exists(disk) else 0
        if size > last_size + 4*1024*1024:          # >4MB growth counts as progress
            last_size = size; last_growth = now; stall_warned = False
        flat = int((now - last_growth) / 60)
        info = screenshot(time.strftime("%H%M"))
        rgb = info[2] if info else None
        print(f"{ts()} +{int((now-T0)/60):3d}min disk={size//1048576}MB flat={flat}min "
              f"agent=no shot_mean_rgb={rgb} budget_left={int((deadline-now)/60)}min", flush=True)
        if flat >= STALL_MIN and not stall_warned:
            stall_warned = True
            print(f"{ts()} WARNING: disk flat for {flat} min and agent not up — probably an "
                  f"interactive screen. Inspect /work/shots/latest.png", flush=True)
    time.sleep(15)

if not ready:
    screenshot("final")
    p.kill(); print(f"{ts()} Windows agent never came up within budget; last screen -> shots/final.png", flush=True)
    sys.exit(2)

screenshot("desktop")

def agent_run(cmd, timeout=180, port=18000):
    """POST /run on the agent: synchronous cmd.exe /c <cmd>, returns dict."""
    body = json.dumps({"cmd": cmd, "timeout": timeout}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/run", data=body, method="POST")
    with urllib.request.urlopen(req, timeout=timeout + 60) as r:
        return json.load(r)

# --- Windows Evaluation activation: nic0 down, nic1 (egress) up, slmgr /ato, swap back
if os.environ.get("ACTIVATE", "1") == "1":
    print(f"{ts()} activation: nic0 down, nic1 up", flush=True)
    hmp("set_link nic0 off"); hmp("set_link nic1 on"); time.sleep(75)   # DHCP + NCSI on the new link
    try:
        print(agent_run(r'ipconfig | findstr /i "IPv4"', 60, 18001).get("output", "")[:300], flush=True)
        r = agent_run(r"cscript //nologo C:\Windows\System32\slmgr.vbs /ato", 400, 18001)
        print(f"{ts()} slmgr /ato ->", (r.get("output") or "")[-400:], flush=True)
        r = agent_run(r"cscript //nologo C:\Windows\System32\slmgr.vbs /dlv", 120, 18001)
        lic = [l for l in (r.get("output") or "").splitlines() if "License Status" in l or "Notification" in l or "expire" in l.lower() or "Name:" in l]
        print(f"{ts()} licence:", lic, flush=True)
    except Exception as e:
        print(f"{ts()} activation step failed: {e}", flush=True)
    hmp("set_link nic1 off"); hmp("set_link nic0 on"); time.sleep(20)
    screenshot("activated")
    for _ in range(30):
        if agent_ready(): break
        time.sleep(5)
    print(f"{ts()} agent on nic0 again: {agent_ready()}", flush=True)

settle = int(os.environ.get("SETTLE_S", "240"))
print(f"{ts()} settling {settle}s before savestate (first-logon background tasks)", flush=True)
time.sleep(settle)
screenshot("presave")
print("saving external RAM state (this can take minutes for 4GB under TCG)...", flush=True)
print(hmp("stop"), flush=True)
print(hmp("migrate_set_parameter max-bandwidth 8g"), flush=True)   # qemu>=8: migrate_set_speed is gone
print(hmp('migrate "exec:gzip -c > /work/win-state.gz"', wait=5), flush=True)
for _ in range(240):
    st = hmp("info migrate")
    if "completed" in st: print("migrate completed", flush=True); break
    if "failed" in st: print("migrate FAILED:", st, flush=True); break
    time.sleep(5)
print(hmp("quit"), flush=True)
try: p.wait(timeout=120)
except Exception: p.kill()
print("windows golden built", flush=True)
PY

podman run --rm --name sandboxgen-winbuild \
    -v "$WORK:/work:rw" -v "$ISO:/iso/win.iso:ro" \
    -e MEM_MB="$MEM_MB" -e SMP="$SMP" -e BOOT_TIMEOUT="$BOOT_TIMEOUT" -e STALL_MIN="$STALL_MIN" -e ACTIVATE="${ACTIVATE:-1}" -e SETTLE_S="${SETTLE_S:-240}" \
    --memory 8g --pids-limit 1024 "$IMAGE" \
    python3 /work/win_build_driver.py

# --- persist golden + state to NFS (survives scratch reclaim) -----------------
# O_DIRECT: a plain cp of 12GB to NFS fills the page cache with dirty pages that
# are charged to the SLURM job cgroup and got a 2G-limited copy OOM-killed.
dd if="$WORK/win-golden.qcow2" of="$OUT/win-golden.qcow2" bs=16M iflag=direct oflag=direct status=none   # backend reads qemu_win_golden
dd if="$WORK/win-state.gz"     of="$OUT/win-state.gz"     bs=16M iflag=direct oflag=direct status=none
(cd "$WORK" && sha256sum win-golden.qcow2 win-state.gz) > "$OUT/win-golden.sha256"
(cd "$OUT" && sha256sum -c win-golden.sha256)
# preflight.sh reads <golden>.sha256 (hash in column 1) as the integrity baseline
awk '/win-golden.qcow2/{print $1}' "$OUT/win-golden.sha256" > "$OUT/win-golden.qcow2.sha256"
podman run --rm -v "$OUT:/o:ro" "$IMAGE" qemu-img info /o/win-golden.qcow2 | tail -6
echo "Windows golden: $OUT/win-golden.qcow2  + state $OUT/win-state.gz"
