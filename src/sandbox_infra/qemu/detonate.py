#!/usr/bin/env python3
"""
detonate.py — runs INSIDE the analysis container (podman --network none).

Boots the golden Linux image on qemu (TCG, no KVM), restores the agent_ready
snapshot, and detonates one sample by driving the in-guest agent over qemu's
loopback hostfwd. The container has no network at all; -netdev user,restrict=on
is a second wall between guest and host. -drive snapshot=on discards every
write, so each task starts from the same golden state (SG-VM-01).

Input  (env):  TASK_DIR=/task, TIMEOUT, GOLDEN=/vm/golden.qcow2, MEM_MB, SMP
Input  (files): $TASK_DIR/sample  (the bytes to run), $TASK_DIR/meta.json
Output (file):  $TASK_DIR/report.json  — CAPE-shaped
The sample is never given network and never reaches the host filesystem
beyond $TASK_DIR (bind-mounted); nothing here is a trust boundary, the VM is.
"""
import json, os, re, socket, subprocess, sys, tarfile, time, urllib.request
from urllib.parse import quote

TASK = os.environ.get("TASK_DIR", "/task")
GOLDEN = os.environ.get("GOLDEN", "/vm/golden.qcow2")
TIMEOUT = int(os.environ.get("TIMEOUT", "60"))
MEM = os.environ.get("MEM_MB", "1536")
SMP = os.environ.get("SMP", "4")
PORT = 18000
meta = json.load(open(f"{TASK}/meta.json"))


def _http(method, path, data=None, timeout=30, raw=False):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return body if raw else json.loads(body or b"{}")


def _wait_ready(proc, deadline):
    while time.time() < deadline and proc.poll() is None:
        try:
            if _http("GET", "/status", timeout=3).get("status") == "ready":
                return True
        except Exception:
            time.sleep(3)
    return False


def _parse_strace(path):
    """Turn an strace log into CAPE-ish process/behaviour data."""
    procs, calls, files_w, files_r, conns, dns, execs = {}, 0, set(), set(), set(), set(), []
    line_re = re.compile(r"^(\d+)\s+[\d.]+\s+(\w+)\((.*)")
    try:
        for line in open(path, errors="replace"):
            m = line_re.match(line)
            if not m:
                continue
            pid, sc, rest = m.group(1), m.group(2), m.group(3)
            procs.setdefault(pid, {"pid": int(pid), "syscalls": 0})
            procs[pid]["syscalls"] += 1
            calls += 1
            if sc in ("open", "openat") and ("O_WRONLY" in rest or "O_RDWR" in rest or "O_CREAT" in rest):
                q = re.search(r'"([^"]+)"', rest)
                if q: files_w.add(q.group(1))
            elif sc in ("open", "openat"):
                q = re.search(r'"([^"]+)"', rest)
                if q: files_r.add(q.group(1))
            elif sc in ("execve", "execveat"):
                q = re.search(r'"([^"]+)"', rest)
                if q: execs.append(q.group(1))
            elif sc == "connect":
                ip = re.search(r'inet_addr\("([^"]+)"\)|sin6?_addr[^"]*"([^"]+)"', rest)
                p = re.search(r'sin6?_port=htons\((\d+)\)', rest)
                addr = (ip.group(1) or ip.group(2)) if ip else None
                if addr: conns.add(f"{addr}:{p.group(1) if p else '?'}")
    except FileNotFoundError:
        pass
    return procs, calls, sorted(files_w), sorted(files_r), sorted(conns), execs


def _parse_pcap(path):
    """DNS query names + TCP SYN destinations (IPv4/IPv6) from the guest's
    tcpdump capture, pure stdlib. Same parser as win_detonate.py; the qemu
    container image has no tcpdump, so the old `tcpdump -r` path returned
    nothing and Linux reports carried no pcap-derived network evidence."""
    import struct
    dns, syns = [], set()
    try:
        d = open(path, "rb").read()
    except OSError:
        return dns, sorted(syns)
    if len(d) < 24:
        return dns, sorted(syns)
    magic = d[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        return dns, sorted(syns)          # pcapng or unknown: not handled
    linktype = struct.unpack(end + "I", d[20:24])[0]

    def qname(q):
        labels, i = [], 0
        try:
            while i < len(q) and q[i]:
                n = q[i]; labels.append(q[i+1:i+1+n].decode("ascii", "replace")); i += 1 + n
        except Exception:
            return ""
        return ".".join(labels)

    def l4_handle(proto, l4, dst):
        if proto == 6 and len(l4) >= 14:
            dport = struct.unpack("!H", l4[2:4])[0]; flags = l4[13]
            if flags & 0x02 and not flags & 0x10:
                syns.add(f"{dst}:{dport}")
        elif proto == 17 and len(l4) >= 20 and struct.unpack("!H", l4[2:4])[0] == 53:
            name = qname(l4[8+12:])
            if name and name not in [x["request"] for x in dns]:
                dns.append({"request": name, "type": "A"})

    def ip_handle(pkt):
        if len(pkt) < 20:
            return
        ver = pkt[0] >> 4
        if ver == 4 and len(pkt) >= 20:
            ihl = (pkt[0] & 0x0f) * 4
            l4_handle(pkt[9], pkt[ihl:], ".".join(str(b) for b in pkt[16:20]))
        elif ver == 6 and len(pkt) >= 40:
            h = pkt[24:40]
            dst6 = ":".join(h[i:i+2].hex().lstrip("0") or "0" for i in range(0, 16, 2))
            l4_handle(pkt[6], pkt[40:], f"[{dst6}]")

    off = 24
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack(end + "IIII", d[off:off+16]); off += 16
        pkt = d[off:off+incl]; off += incl
        if linktype == 1 and len(pkt) >= 14:                 # Ethernet
            et = pkt[12:14]
            if et in (b"\x08\x00", b"\x86\xdd"):
                ip_handle(pkt[14:])
        elif linktype == 113 and len(pkt) >= 16:            # Linux cooked (tcpdump -i any)
            if pkt[14:16] in (b"\x08\x00", b"\x86\xdd"):
                ip_handle(pkt[16:])
        elif linktype == 276 and len(pkt) >= 20:            # Linux cooked v2
            if pkt[0:2] in (b"\x08\x00", b"\x86\xdd"):
                ip_handle(pkt[20:])
        elif linktype == 101:                                # raw IP
            ip_handle(pkt)
    return dns, sorted(syns)


# the guest's own resolver/gateway traffic is not sample behaviour
_LOCAL_NET = ("10.0.2.", "127.", "224.", "239.", "255.", "[fe80", "[fec0", "[ff02", "[ff05", "[::")


def main():
    sample = f"{TASK}/sample"
    size = os.path.getsize(sample)
    mon = "/tmp/mon.sock"
    serial = f"{TASK}/guest-serial.log"
    # SG-VM-01: a fresh copy-on-write overlay backed by the immutable golden
    # image. Every guest write lands in this overlay, which is discarded with
    # the task dir; the golden image (mounted read-only) is never modified, so
    # each task provably starts from the same clean baseline. (loadvm + a RAM
    # snapshot would be faster but cannot combine with a discard overlay; a
    # fresh boot to the agent is ~30s under TCG, which is acceptable.)
    overlay = f"{TASK}/overlay.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2",
                    "-b", GOLDEN, "-F", "qcow2", overlay], check=True)
    cmd = ["qemu-system-x86_64", "-accel", "tcg,thread=multi", "-m", MEM, "-smp", SMP,
           "-cpu", "max", "-nographic", "-display", "none",
           "-drive", f"file={overlay},if=virtio,format=qcow2",
           # restrict=on: guest cannot reach the host or the outside; the one
           # hole is the agent control port, host->guest only (hostfwd).
           "-netdev", "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:%d-:8000" % PORT,
           "-device", "virtio-net-pci,netdev=n0",
           "-device", "virtio-rng-pci",
           "-monitor", f"unix:{mon},server,nowait",
           "-serial", f"file:{serial}"]
    started = time.time()
    proc = subprocess.Popen(cmd)
    report = {"backend": "qemu-tcg", "target": {"file": {"sha256": meta["sha256"], "name": meta.get("name", "sample")}},
              "info": {"machine": "qemu-linux", "package": meta.get("package"), "route": "drop"},
              "signatures": [], "behavior": {"processes": []},
              "network": {"dns": [], "tcp": [], "http": [], "hosts": []},
              "malscore": 0.0, "sandboxgen": {}}
    try:
        if not _wait_ready(proc, started + max(180, TIMEOUT)):
            report["sandboxgen"]["error"] = "guest agent did not become ready"
            json.dump(report, open(f"{TASK}/report.json", "w")); return 0
        with open(sample, "rb") as f:
            stored_name = quote(meta.get("name", "sample"), safe="")
            _http("POST", f"/store?name={stored_name}", data=f.read(), timeout=120)
        interp = meta.get("interpreter")
        _http("POST", "/execute",
              data=json.dumps({"path": f"/tmp/task/{meta.get('name','sample')}",
                               "timeout": TIMEOUT, "interpreter": interp}).encode(), timeout=30)
        deadline = time.time() + TIMEOUT + 90
        state = "running"
        while time.time() < deadline:
            try:
                state = _http("GET", "/poll", timeout=10).get("state")
            except Exception:
                state = "running"
            if state == "done":
                break
            time.sleep(5)
        blob = _http("GET", "/result", timeout=120, raw=True)
        with open(f"{TASK}/result.tar.gz", "wb") as f:
            f.write(blob)
    finally:
        try:
            s = socket.socket(socket.AF_UNIX); s.connect(mon)
            s.sendall(b"quit\n"); s.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=60)
        except Exception:
            proc.kill()

    # Unpack and shape
    try:
        with tarfile.open(f"{TASK}/result.tar.gz") as tf:
            tf.extractall(TASK)
    except Exception as e:
        report["sandboxgen"]["error"] = f"no result tarball: {e}"
        json.dump(report, open(f"{TASK}/report.json", "w")); return 0

    td = f"{TASK}/task"
    run = {}
    try:
        run = json.load(open(f"{td}/run.json"))
    except Exception:
        pass
    procs, calls, fw, fr, conns, execs = _parse_strace(f"{td}/strace.log")
    dns, syns = _parse_pcap(f"{td}/net.pcap")
    syns = [x for x in syns if not x.startswith(_LOCAL_NET)]
    conns = [c for c in conns if not c.startswith(_LOCAL_NET)]   # strace connect() to the local resolver stub etc.
    dns = [q for q in dns if not q["request"].endswith((".in-addr.arpa", ".ip6.arpa"))]
    hosts = sorted({x.rsplit(":", 1)[0] for x in syns} | {c.split(":")[0] for c in conns if ":" in c})
    report["behavior"]["processes"] = list(procs.values())
    report["behavior"]["summary"] = {"file_written": fw, "file_read": fr[:200],
                                     "executed": execs}
    report["network"]["hosts"] = hosts
    report["network"]["dns"] = dns
    report["network"]["tcp"] = [{"dst": c} for c in sorted(set(conns) | set(syns))]
    # A simple malscore: any child process, any write outside its own dir, or
    # any network attempt (blocked, but attempted) is signal.
    signal = (len(procs) > 1) or bool([f for f in fw if not f.startswith("/tmp/task")]) \
             or bool(conns) or bool(syns) or bool(dns)
    report["malscore"] = 1.0 if signal else 0.0
    if run.get("timed_out"):
        report["signatures"].append({"name": "long_running_or_timeout", "severity": 1})
    if [f for f in fw if not f.startswith("/tmp/task")]:
        report["signatures"].append({"name": "writes_outside_workdir", "severity": 2})
    if conns or syns or dns:
        report["signatures"].append({"name": "network_activity_attempted", "severity": 2})
    report["sandboxgen"] = {"exit_code": run.get("exit_code"), "timed_out": run.get("timed_out"),
                            "syscalls": calls, "process_count": len(procs),
                            "modified_files": run.get("modified_files", [])[:500],
                            "duration_s": round(time.time() - started, 1),
                            "size_bytes": size, "route_enforced": "drop"}
    json.dump(report, open(f"{TASK}/report.json", "w"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
