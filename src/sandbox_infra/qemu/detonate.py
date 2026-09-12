#!/usr/bin/env python3
"""
detonate.py — runs INSIDE the analysis container (podman --network none).

Boots a fresh overlay of the golden Linux image on qemu (TCG, no KVM)
and detonates one sample by driving the in-guest agent over qemu's
loopback hostfwd. The container has no network at all; -netdev user,restrict=on
is a second wall between guest and host. Discarding the per-task overlay
leaves the golden state unchanged (SG-VM-01).

Input  (env):  TASK_DIR=/task, TIMEOUT, GOLDEN=/vm/golden.qcow2, MEM_MB, SMP
Input  (files): $TASK_DIR/sample  (the bytes to run), $TASK_DIR/meta.json
Output (file):  $TASK_DIR/report.json  — CAPE-shaped
The sample is never given network and never reaches the host filesystem
beyond $TASK_DIR (bind-mounted); nothing here is a trust boundary, the VM is.
"""
import ast, json, os, re, socket, subprocess, sys, tarfile, time, urllib.request
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
    """Keep syscall outcomes distinct from attempts; never infer successful exec."""
    procs, calls, pending, sockets = {}, 0, {}, {}
    written, read, opened_w, opened_r, write_attempts, execs, exec_attempts = set(), set(), set(), set(), set(), [], []
    events, exec_events, connections = [], [], []
    truncated = 0
    prefix = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+([\d.]+)\s+(.*)")

    def strings(text):
        result = []
        for item in re.findall(r'"(?:\\.|[^"\\])*"', text):
            try:
                result.append(ast.literal_eval(item))
            except (ValueError, SyntaxError):
                result.append(item[1:-1])
        return result

    try:
        handle = open(path, errors="replace")
    except FileNotFoundError:
        handle = []
    try:
        for line in handle:
            m = prefix.match(line)
            if not m:
                continue
            pid, timestamp, body = m.groups()
            if "<unfinished ...>" in body:
                pending[pid] = body.split("<unfinished ...>", 1)[0]
                continue
            resumed = re.match(r"<\.\.\. (\w+) resumed>(.*)", body)
            if resumed:
                start = pending.pop(pid, "")
                if not start.startswith(resumed.group(1) + "("):
                    continue
                body = start + resumed.group(2)
            m = re.match(r"(\w+)\((.*)\)\s+=\s+(0x[0-9a-f]+|-?\d+|\?)(?:\s+([A-Z][A-Z0-9_]+))?", body)
            if not m:
                continue
            sc, rest, returned, errno = m.groups()
            result = None if returned == "?" else int(returned, 16 if returned.startswith("0x") else 10)
            success = None if result is None else result >= 0
            quoted = strings(rest)
            procs.setdefault(pid, {"pid": int(pid), "syscalls": 0})
            procs[pid]["syscalls"] += 1
            calls += 1
            event = {"pid": int(pid), "timestamp": timestamp, "syscall": sc,
                     "result": result, "success": success, "errno": errno}
            if sc in ("open", "openat", "openat2") and quoted:
                event["path"] = quoted[0]
                writable = any(flag in rest for flag in ("O_WRONLY", "O_RDWR", "O_CREAT"))
                if writable:
                    write_attempts.add(quoted[0])
                if success:
                    sockets.pop((pid, result), None)
                    (opened_w if writable else opened_r).add(quoted[0])
            elif sc in ("write", "writev", "pwrite64", "pwritev", "read", "readv", "pread64", "preadv"):
                fd_path = re.match(r"\d+<(/.*?)>,\s", rest)
                if fd_path:
                    path_value = fd_path.group(1)
                    device = re.search(r"<(char|block) \d+:\d+>$", path_value)
                    if device:
                        event["device_type"] = device.group(1)
                        path_value = path_value[:device.start()]
                    event["path"] = path_value
                    is_write = "write" in sc
                    if is_write:
                        write_attempts.add(path_value)
                    if result is not None and result > 0:
                        (written if is_write else read).add(path_value)
            elif sc in ("execve", "execveat") and quoted:
                event.update(image=quoted[0], arguments=quoted)
                exec_attempts.append(quoted[0])
                exec_events.append(event)
                if success:
                    execs.append(quoted[0])
                    procs[pid]["image"] = quoted[0]
            elif sc == "socket" and success:
                parts = [part.strip() for part in rest.split(",")]
                protocol = "unknown"
                if len(parts) == 3 and parts[0] in ("AF_INET", "AF_INET6"):
                    if "SOCK_STREAM" in parts[1] and parts[2] in ("0", "IPPROTO_IP", "IPPROTO_TCP"):
                        protocol = "tcp"
                    elif "SOCK_DGRAM" in parts[1] and parts[2] in ("0", "IPPROTO_IP", "IPPROTO_UDP"):
                        protocol = "udp"
                sockets[(pid, result)] = protocol
            elif sc == "close" and success:
                fd = re.match(r"(\d+)", rest)
                if fd:
                    sockets.pop((pid, int(fd.group(1))), None)
            elif sc in ("dup", "dup2", "dup3") and success:
                fd = re.match(r"(\d+)", rest)
                sockets[(pid, result)] = sockets.get((pid, int(fd.group(1))), "unknown") if fd else "unknown"
            elif sc == "close_range" and success:
                sockets = {key: value for key, value in sockets.items() if key[0] != pid}
            elif sc == "connect":
                ip = re.search(r'inet_addr\("([^"]+)"\)|sin6?_addr[^"]*"([^"]+)"', rest)
                p = re.search(r'sin6?_port=htons\((\d+)\)', rest)
                addr = (ip.group(1) or ip.group(2)) if ip else None
                fd = re.match(r"(\d+)", rest)
                protocol = "tcp" if "<TCP" in rest else "udp" if "<UDP" in rest else sockets.get((pid, int(fd.group(1))), "unknown") if fd else "unknown"
                if addr:
                    event.update(dst=f"{addr}:{p.group(1) if p else '?'}", protocol=protocol,
                                 established=success if protocol == "tcp" else None,
                                 attribution="traced_process")
                    connections.append(event.copy())
            if sc in ("open", "openat", "openat2", "write", "writev", "pwrite64", "pwritev", "execve", "execveat", "connect"):
                if len(events) < 2000:
                    events.append(event)
                else:
                    truncated += 1
    finally:
        if hasattr(handle, "close"):
            handle.close()
    return {"processes": list(procs.values()), "syscalls": calls,
            "summary": {"file_written": sorted(written), "file_read": sorted(read)[:200],
                        "file_opened_for_write": sorted(opened_w), "file_opened_for_read": sorted(opened_r)[:200],
                        "file_write_attempted": sorted(write_attempts), "executed": execs,
                        "execution_attempted": exec_attempts},
            "events": events, "events_truncated": truncated,
            "exec_events": exec_events, "connections": connections}


def _execution_health(trace, run, sample_path, interpreter=None):
    roots = []
    for event in trace["exec_events"]:
        args = event.get("arguments", [])
        target = event.get("image") == sample_path
        script = interpreter and event.get("image") == interpreter and len(args) > 2 and args[2] == sample_path
        if event.get("success") is True and (target or script):
            roots.append(event["pid"])
    errors = [f"{key}: {run[key]}" for key in ("error", "launch_error", "wait_error", "export_error") if run.get(key)]
    if not run:
        errors.append("guest run metadata is missing")
    if not roots:
        errors.append("no successful exec of the submitted sample or its selected interpreter observed")
    return {"evidence_schema_version": 2, "execution_valid": not errors,
            "execution_errors": errors, "sample_process_root_found": bool(roots),
            "sample_process_root_pids": sorted(set(roots))}


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
              "malscore": 0.0, "sandboxgen": {"evidence_schema_version": 2,
                  "execution_valid": False, "sample_process_root_found": False}}
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
    trace = _parse_strace(f"{td}/strace.log")
    procs, calls = trace["processes"], trace["syscalls"]
    fw = trace["summary"]["file_written"]
    dns, syns = _parse_pcap(f"{td}/net.pcap")
    syns = [x for x in syns if not x.startswith(_LOCAL_NET)]
    connections = [c for c in trace["connections"] if not c["dst"].startswith(_LOCAL_NET)]
    dns = [q for q in dns if not q["request"].endswith((".in-addr.arpa", ".ip6.arpa"))]
    hosts = sorted({x.rsplit(":", 1)[0] for x in syns} | {c["dst"].rsplit(":", 1)[0] for c in connections})
    report["behavior"]["processes"] = procs
    report["behavior"]["summary"] = trace["summary"]
    report["behavior"]["syscall_events"] = trace["events"]
    report["network"]["hosts"] = hosts
    report["network"]["dns"] = [dict(q, attribution="guest_network_capture_unattributed") for q in dns]
    report["network"]["connections"] = connections
    tcp = [c for c in connections if c["protocol"] == "tcp"]
    seen = {c["dst"] for c in tcp}
    tcp += [{"dst": c, "protocol": "tcp", "established": False,
             "attribution": "guest_network_capture_unattributed"} for c in sorted(set(syns) - seen)]
    report["network"]["tcp"] = tcp
    report["network"]["udp"] = [c for c in connections if c["protocol"] == "udp"]
    # A simple malscore: any child process, any write outside its own dir, or
    # any network attempt (blocked, but attempted) is signal.
    signal = (len(procs) > 1) or bool([f for f in fw if not f.startswith("/tmp/task")]) \
             or bool(connections) or bool(syns) or bool(dns)
    report["malscore"] = 1.0 if signal else 0.0
    if run.get("timed_out"):
        report["signatures"].append({"name": "long_running_or_timeout", "severity": 1})
    if [f for f in fw if not f.startswith("/tmp/task")]:
        report["signatures"].append({"name": "writes_outside_workdir", "severity": 2})
    if connections or syns or dns:
        report["signatures"].append({"name": "network_activity_attempted", "severity": 2})
    report["sandboxgen"] = {"exit_code": run.get("exit_code"), "timed_out": run.get("timed_out"),
                            "syscalls": calls, "process_count": len(procs),
                            "modified_files": run.get("modified_files", [])[:500],
                            "duration_s": round(time.time() - started, 1),
                            "size_bytes": size, "route_enforced": "drop",
                            "syscall_events_truncated": trace["events_truncated"],
                            "effective_environment": meta.get("effective_environment", {}),
                            "unsupported_options": meta.get("unsupported_options", []),
                            "modified_files_attribution": "guest_wide_candidates_not_sample_attributed"}
    report["sandboxgen"].update(_execution_health(trace, run, f"/tmp/task/{meta.get('name', 'sample')}", meta.get("interpreter")))
    json.dump(report, open(f"{TASK}/report.json", "w"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
