#!/usr/bin/env python3
"""
win_detonate.py — Windows detonation inside the analysis container.

Same four walls as the Linux path (detonate.py): --network none container,
qemu TCG, guest restrict=on, per-task COW overlay off a read-only golden.
Difference: the guest is Windows, resumed from an EXTERNAL RAM savestate
(-incoming) so it does not boot (Windows boot under TCG is many minutes),
and behaviour comes from Sysmon (ETW) instead of strace.

Env: TASK_DIR=/task, TIMEOUT, GOLDEN=/vm/win-golden.qcow2,
     STATE=/vm/win-state.gz, MEM_MB, SMP
Files in: $TASK_DIR/sample, $TASK_DIR/meta.json
File out: $TASK_DIR/report.json  (CAPE-shaped)
"""
import json, os, re, socket, subprocess, sys, time, zipfile, urllib.request
from urllib.parse import quote

TASK = os.environ.get("TASK_DIR", "/task")
GOLDEN = os.environ.get("GOLDEN", "/vm/win-golden.qcow2")
STATE = os.environ.get("STATE", "/vm/win-state.gz")
TIMEOUT = int(os.environ.get("TIMEOUT", "120"))
MEM = os.environ.get("MEM_MB", "4096")
# MEM/SMP/CPU must equal what the golden's RAM state was saved with
# (build_windows_guest.sh: -m 4096 -smp 8 -cpu Nehalem) or -incoming fails.
SMP = os.environ.get("SMP", "8")
CPU = os.environ.get("CPU_MODEL", "Nehalem")
PORT = 18000


def _http(method, path, data=None, timeout=30, raw=False):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return body if raw else json.loads(body or b"{}")


def _hmp(mon, line, wait=0.5):
    """one HMP command on the monitor socket; '' on any failure."""
    try:
        s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(mon)
        time.sleep(0.2); s.recv(65536)
        s.sendall((line + "\n").encode()); time.sleep(wait)
        try:
            out = s.recv(65536)
        except Exception:
            out = b""
        s.close()
        return out.decode(errors="replace")
    except Exception:
        return ""


def _screenshot(mon, dst_png):
    """screendump via the monitor and convert PPM->PNG (stdlib only); best effort."""
    import struct, zlib
    ppm = dst_png + ".ppm"
    _hmp(mon, f"screendump {ppm}", wait=2)
    try:
        d = open(ppm, "rb").read(); parts = []; i = 0
        while len(parts) < 4:
            while d[i:i+1].isspace(): i += 1
            j = i
            while not d[j:j+1].isspace(): j += 1
            parts.append(d[i:j]); i = j
        i += 1; w, h = int(parts[1]), int(parts[2]); px = d[i:]
        raw = b"".join(b"\x00" + px[y*w*3:(y+1)*w*3] for y in range(h))
        ch = lambda t, b: struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xffffffff)
        open(dst_png, "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                                  + ch(b"IDAT", zlib.compress(raw, 6)) + ch(b"IEND", b""))
        os.remove(ppm)
    except Exception:
        pass


def _wait_ready(proc, deadline, mon=None):
    # The golden's RAM state was saved after an HMP "stop", and the run state
    # travels with the migration stream: once -incoming completes the guest
    # sits *paused* until it gets "cont". Nudge it whenever it is not running.
    last_cont = 0
    while time.time() < deadline and proc.poll() is None:
        try:
            if _http("GET", "/status", timeout=4).get("status") == "ready":
                return True
        except Exception:
            pass
        if mon and time.time() - last_cont > 5:
            last_cont = time.time()
            st = _hmp(mon, "info status")
            if "paused" in st and "inmigrate" not in st:
                _hmp(mon, "set_link nic1 off"); _hmp(mon, "set_link nic0 on")
                _hmp(mon, "cont")
        time.sleep(3)
    return False


# Sysmon event ids -> what they tell us
_SYS_PROC_CREATE = "1"
_SYS_NET_CONNECT = "3"
_SYS_FILE_CREATE = "11"
_SYS_REG_SET     = ("12", "13", "14")
_SYS_DNS         = "22"


def _parse_sysmon_xml(path):
    """wevtutil qe /f:xml output: concatenated <Event> elements, no root."""
    import xml.etree.ElementTree as ET
    procs, files_w, conns, dns, regs, images = {}, set(), set(), [], set(), []
    loads = []
    try:
        raw = open(path, "rb").read()
    except FileNotFoundError:
        return None
    # wevtutil's redirected output is in the console ANSI code page (cp1252 on
    # en-US), NOT utf-16: an even-length cp1252 file "decodes" as utf-16 into
    # garbage that parses as zero events (bit us twice). utf-8 first for a BOM-
    # less UTF-8 export, then cp1252; never utf-16.
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        txt = raw.decode("cp1252", errors="replace")
    txt = txt.lstrip("\ufeff")
    try:
        root = ET.fromstring("<Events>" + txt + "</Events>")
    except ET.ParseError as e:
        print(f"sysmon.xml parse error: {e}", file=sys.stderr)
        return None
    if len(root) == 0 and b"<Event " in raw:
        print("sysmon.xml: decoded text yielded no <Event> elements (encoding?)", file=sys.stderr)
        return None
    for ev in root:
        eid, data = None, {}
        for el in ev.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag == "EventID":
                eid = (el.text or "").strip()
            elif tag == "Data" and el.get("Name"):
                data[el.get("Name")] = (el.text or "").strip()
        if eid == _SYS_PROC_CREATE:
            pid = data.get("ProcessId", "?"); img = data.get("Image", "?")
            procs[pid] = {"pid": pid, "ppid": data.get("ParentProcessId"), "image": img,
                          "cmdline": data.get("CommandLine", ""), "user": data.get("User")}
            images.append(img)
        elif eid == "7":
            loads.append((data.get("ProcessId"), data.get("ImageLoaded", "")))
        elif eid == _SYS_NET_CONNECT:
            if data.get("DestinationIp") and data.get("Initiated", "true").lower() == "true":
                conns.add((data.get("ProcessId"), f"{data['DestinationIp']}:{data.get('DestinationPort','')}"))
        elif eid == _SYS_FILE_CREATE:
            if data.get("TargetFilename"):
                files_w.add((data.get("ProcessId"), data["TargetFilename"]))
        elif eid in _SYS_REG_SET:
            if data.get("TargetObject"):
                regs.add((data.get("ProcessId"), data["TargetObject"]))
        elif eid == _SYS_DNS:
            if data.get("QueryName"):
                dns.append((data.get("ProcessId"), data["QueryName"]))
    for pid, loaded in loads:
        if pid in procs:
            procs[pid].setdefault("loaded_images", []).append(loaded)
    return procs, files_w, conns, dns, regs, images


def _sample_tree(procs, sample_name, launch=None):
    """Exact image match for EXEs; explicit loader + ImageLoad for DLLs.

    Mentioning a sample in OpenWith, a shell, or an error dialog is not proof
    of execution. A DLL loader process without an ImageLoad is not proof either.
    """
    path = f"C:\\task\\{sample_name}".lower()
    launch = launch or {"package": "exe"}
    if launch.get("package") == "dll":
        directory = "syswow64" if launch.get("architecture") == "x86" else "system32"
        loader = f"c:\\windows\\{directory}\\rundll32.exe"
        args = re.compile(r'(?:^|\s)"?' + re.escape(path) + r'"?,' +
                          re.escape(launch.get("function") or "") + r'(?:\s|$)', re.I)
        root = [p for p in procs.values() if p.get("image", "").lower() == loader
                and args.search(p.get("cmdline", ""))
                and path in [i.lower() for i in p.get("loaded_images", [])]]
    else:
        root = [p for p in procs.values() if p.get("image", "").lower() == path]
    tree = {p["pid"] for p in root}
    grew = True
    while grew:
        grew = False
        for p in procs.values():
            if p.get("ppid") in tree and p["pid"] not in tree:
                tree.add(p["pid"]); grew = True
    return tree


def _start_sample(meta):
    """Stage the trusted runner on this disposable guest; never use old /execute.

    The golden image remains untouched. All model parameters travel as JSON,
    not as PowerShell source or fragments of the fixed transport command.
    """
    launch = meta.get("launch")
    if not isinstance(launch, dict) or launch.get("version") != 1:
        raise ValueError("missing validated launch metadata; submit via QemuCapeClient")
    with open("/run-sample.ps1", "rb") as f:
        runner = f.read()
    request = json.dumps({"path": f"C:\\task\\{meta['name']}", "timeout": TIMEOUT,
                          "launch": launch}).encode()
    _http("POST", "/store?name=run-sample.ps1", data=runner, timeout=120)
    _http("POST", "/store?name=launch-request.json", data=request, timeout=120)
    command = (
        'powershell.exe -NoProfile -NonInteractive -Command "'
        "Start-Process -FilePath 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' "
        "-ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\task\\run-sample.ps1' "
        '-WindowStyle Hidden"'
    )
    reply = _http("POST", "/run", data=json.dumps({"cmd": command, "timeout": 60}).encode(), timeout=120)
    if reply.get("timed_out") or reply.get("exit_code") not in (None, 0):
        raise RuntimeError("guest could not start the trusted per-task runner")
    import hashlib
    return hashlib.sha256(runner).hexdigest()


def _execution_health(run, tree):
    reasons = [f"{key}: {run[key]}" for key in ("launch_error", "wait_error", "export_error") if run.get(key)]
    if run.get("launcher_version") != 1:
        reasons.append("trusted per-task runner did not produce a versioned result")
    if not tree:
        reasons.append("no sample executable or DLL ImageLoad observed")
    waited = run.get("waited_s")
    if not isinstance(waited, (int, float)) or waited < 0.8 * TIMEOUT:
        reasons.append("guest observation window shorter than requested")
    return {"execution_valid": not reasons, "execution_errors": reasons}


def _endpoint_host(endpoint):
    """Host portion of an IPv4 or bracketed/unbracketed IPv6 host:port."""
    return endpoint.rsplit(":", 1)[0].strip("[]")


def _update_sandboxgen(report, fields):
    """Merge runtime metadata without discarding an earlier health error."""
    report.setdefault("sandboxgen", {}).update(fields)


def _shape_attributed_behavior(procs, tree, files_own, regs_own, files_all, regs_all):
    """Keep sample evidence separate from diagnostic OS/harness noise."""
    tree_procs = [p for p in procs.values() if p["pid"] in tree]
    summary = {
        "file_written": files_own[:500],
        "regkey_written": regs_own[:500],
        "images": [p["image"] for p in tree_procs][:200],
    }
    background = {
        "processes": [p["image"] for p in procs.values() if p["pid"] not in tree][:100],
        "file_written_count": len(files_all) - len(files_own),
        "regkey_written_count": len(regs_all) - len(regs_own),
    }
    return tree_procs, summary, background


def _parse_pcap(path):
    """DNS query names + TCP SYN destinations (IPv4 and IPv6) from the guest-side
    pcap (pure stdlib): what the isolated guest *tried*; Sysmon only sees
    established flows, and raw resolvers (nslookup) bypass its DNS events."""
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
        return dns, sorted(syns)
    # QEMU filter-dump emits Ethernet pcap. Refuse other link types rather than
    # interpreting arbitrary offsets as an Ethernet/IP header.
    if struct.unpack(end + "I", d[20:24])[0] != 1:
        return dns, sorted(syns)

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

    off = 24
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack(end + "IIII", d[off:off+16]); off += 16
        pkt = d[off:off+incl]; off += incl
        if len(pkt) < 14:
            continue
        et = pkt[12:14]
        if et == b"\x08\x00" and len(pkt) >= 34:
            ihl = (pkt[14] & 0x0f) * 4
            l4_handle(pkt[23], pkt[14+ihl:], ".".join(str(b) for b in pkt[30:34]))
        elif et == b"\x86\xdd" and len(pkt) >= 54:
            h = pkt[38:54]
            dst6 = ":".join(h[i:i+2].hex().lstrip("0") or "0" for i in range(0, 16, 2))
            l4_handle(pkt[20], pkt[54:], f"[{dst6}]")
    return dns, sorted(syns)


# Windows' own chatter on the wire (telemetry, NCSI, Edge, Store); the pcap has
# no pid, so these are dropped by name. Sysmon's pid-attributed DNS is not filtered.
_DNS_NOISE = (".microsoft.com", ".msftncsi.com", ".msftconnecttest.com", ".skype.com",
              ".static.microsoft", ".windowsupdate.com", ".live.com", ".bing.com", ".msn.com",
              ".office.com", ".office.net", ".windows.com", ".azureedge.net", ".msedge.net",
              ".digicert.com", ".verisign.com", ".in-addr.arpa", ".ip6.arpa", ".local", "wpad")


def _parse_sysmon(path):
    procs, files_w, conns, dns, regs, images = {}, set(), set(), [], set(), []
    kv = lambda s, k: (re.search(rf"{k}:\s*([^|]+)", s) or [None, None])[1]
    try:
        for line in open(path, encoding="utf-8", errors="replace"):
            parts = line.split("\t", 2)
            if len(parts) < 3:
                continue
            eid, _, msg = parts
            eid = eid.strip()
            if eid == _SYS_PROC_CREATE:
                pid = (kv(msg, "ProcessId") or "?").strip()
                img = (kv(msg, "Image") or "?").strip()
                procs[pid] = {"pid": pid, "image": img,
                              "cmdline": (kv(msg, "CommandLine") or "").strip()}
                images.append(img)
            elif eid == _SYS_NET_CONNECT:
                dip = (kv(msg, "DestinationIp") or "").strip()
                dport = (kv(msg, "DestinationPort") or "").strip()
                if dip:
                    conns.add(f"{dip}:{dport}")
            elif eid == _SYS_FILE_CREATE:
                tf = (kv(msg, "TargetFilename") or "").strip()
                if tf:
                    files_w.add(tf)
            elif eid in _SYS_REG_SET:
                to = (kv(msg, "TargetObject") or "").strip()
                if to:
                    regs.add(to)
            elif eid == _SYS_DNS:
                q = (kv(msg, "QueryName") or "").strip()
                if q:
                    dns.append({"request": q, "type": "A"})
    except FileNotFoundError:
        pass
    return (procs, {(None, f) for f in files_w}, {(None, c) for c in conns},
            [(None, q["request"]) for q in dns], {(None, r) for r in regs}, images)


def main():
    meta = json.load(open(f"{TASK}/meta.json"))
    sample = f"{TASK}/sample"
    size = os.path.getsize(sample)
    mon = "/tmp/mon.sock"
    overlay = f"{TASK}/overlay.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2",
                    "-b", GOLDEN, "-F", "qcow2", overlay], check=True)
    cmd = ["qemu-system-x86_64", "-accel", "tcg,thread=multi", "-m", MEM, "-smp", SMP,
           "-cpu", CPU, "-machine", "pc", "-display", "none", "-vga", "std",
           "-drive", f"file={overlay},if=ide,format=qcow2",
           # the state was saved with two IDE CD-ROM drives (install + media
           # ISOs); the device tree must match on resume, media may be absent.
           "-drive", "if=ide,media=cdrom", "-drive", "if=ide,media=cdrom",
           # restrict=on: guest reaches neither host nor outside; only the
           # agent control port, host->guest via hostfwd.
           "-netdev", "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:%d-:8000" % PORT,
           "-device", "e1000,netdev=n0,id=nic0",
           # nic1 exists in the golden (used once at build time for licence
           # activation); it must exist here too for the RAM state to load.
           # Restricted AND link down: no egress path at analysis time.
           "-netdev", "user,id=n1,restrict=on,net=10.0.3.0/24",
           "-device", "e1000,netdev=n1,id=nic1",
           "-object", f"filter-dump,id=dump0,netdev=n0,file={TASK}/net.pcap,maxlen=256",
           "-incoming", f"exec:gzip -dc {STATE}",     # resume, no Windows boot
           "-monitor", f"unix:{mon},server,nowait",
           "-serial", f"file:{TASK}/guest-serial.log"]
    started = time.time()
    proc = subprocess.Popen(cmd)
    report = {"backend": "qemu-tcg-windows",
              "target": {"file": {"sha256": meta["sha256"], "name": meta.get("name", "sample.exe")}},
              "info": {"machine": "qemu-windows", "package": meta.get("package"), "route": "drop"},
              "signatures": [], "behavior": {"processes": []},
              "network": {"dns": [], "tcp": [], "http": [], "hosts": []},
              "malscore": 0.0, "sandboxgen": {"launch": meta.get("launch"),
                  "unsupported_options": (meta.get("launch") or {}).get("unsupported_options", [])}}
    try:
        if not _wait_ready(proc, started + max(600, TIMEOUT), mon):
            report["sandboxgen"]["error"] = "windows guest agent did not resume/ready"
            json.dump(report, open(f"{TASK}/report.json", "w")); return 0
        # slirp restrict=on hands out no default gateway, so connect() to any
        # outside address fails inside the guest before a SYN reaches the wire
        # and nothing is observable. A default route to the (dropping) gateway
        # puts the attempts on the wire for the pcap. Agent >= v3 has /run.
        try:
            r = _http("POST", "/run", data=json.dumps(
                {"cmd": "route add 0.0.0.0 mask 0.0.0.0 10.0.2.2 metric 5 & route print -4 | findstr /c:\"0.0.0.0\"",
                 "timeout": 60}).encode(), timeout=120)
            print("route:", (r.get("output") or "").strip()[:300], file=sys.stderr, flush=True)
        except Exception as e:
            print(f"route add skipped ({e})", file=sys.stderr, flush=True)
        with open(sample, "rb") as f:
            stored_name = quote(meta.get("name", "sample.exe"), safe="")
            _http("POST", f"/store?name={stored_name}", data=f.read(), timeout=120)
        try:
            report["sandboxgen"]["runner_sha256"] = _start_sample(meta)
        except Exception as e:
            report["sandboxgen"].update(error=f"trusted runner startup failed: {e}", execution_valid=False)
            json.dump(report, open(f"{TASK}/report.json", "w")); return 0
        # periodic screenshots of the guest console while the sample runs: the
        # sample now lives in the interactive session, so its windows/dialogs are
        # visible here. Host-side (qemu VGA), so nothing in the guest can hide it.
        import threading
        shots_dir = f"{TASK}/shots"; os.makedirs(shots_dir, exist_ok=True)
        shots = []; stop_shots = threading.Event()
        def _shooter():
            n = 0; last = b""
            while not stop_shots.is_set() and n < int(os.environ.get("MAX_SHOTS", "60")):
                png = f"{shots_dir}/{n:03d}.png"
                _screenshot(mon, png)
                try:
                    cur = open(png, "rb").read()
                    if cur == last:                    # unchanged frame: drop it
                        os.remove(png)
                    else:
                        last = cur; shots.append(os.path.basename(png)); n += 1
                except OSError:
                    pass
                stop_shots.wait(int(os.environ.get("SHOT_EVERY", "15")))
        threading.Thread(target=_shooter, daemon=True).start()
        # HOST-side dialog driver: samples (installers, SmartScreen, "renamed
        # file", consent prompts) stall on modal dialogs waiting for a human. We
        # send button-accelerator keystrokes through the qemu monitor — Alt+Y
        # (&Yes), Alt+R (&Run/Run anyway), Alt+I (&Install/I agree), Alt+A
        # (Accept/Allow), and Enter (default OK) — advancing dialogs without any
        # in-guest agent. We never send Alt+N (&No) or Alt+C (&Cancel). Robust
        # under TCG where in-guest UI Automation hangs. Verified 2026-09-09.
        drive_keys = os.environ.get("DIALOG_KEYS", "ret").split()
        clicks_log = []
        def _driver():
            while not stop_shots.is_set():
                for k in drive_keys:
                    if stop_shots.is_set(): break
                    _hmp(mon, f"sendkey {k}", 0.2)
                    time.sleep(0.6)
                stop_shots.wait(int(os.environ.get("DIALOG_EVERY", "4")))
        if os.environ.get("DRIVE_DIALOGS", "1") == "1":
            threading.Thread(target=_driver, daemon=True).start()
        # grace beyond the sample timeout: Start-Job spawn + Sysmon evtx export
        # + Get-WinEvent message formatting are all slow under TCG
        deadline = time.time() + TIMEOUT + int(os.environ.get("POLL_GRACE", "900"))
        last_state = None
        while time.time() < deadline:
            try:
                state = _http("GET", "/poll", timeout=10).get("state")
            except Exception as e:
                state = f"err:{e}"
            if state != last_state:
                print(f"[{time.time()-started:6.1f}s] guest state: {state}", file=sys.stderr, flush=True)
                last_state = state
            if state == "done":
                break
            time.sleep(5)
        stop_shots.set()
        blob = _http("GET", "/result", timeout=180, raw=True)
        with open(f"{TASK}/result.zip", "wb") as f:
            f.write(blob)
    finally:
        _screenshot(mon, f"{TASK}/final.png")      # what the guest showed at the end
        try:
            s = socket.socket(socket.AF_UNIX); s.connect(mon); s.sendall(b"quit\n"); s.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=60)
        except Exception:
            proc.kill()

    try:
        with zipfile.ZipFile(f"{TASK}/result.zip") as z:
            z.extractall(f"{TASK}/task")
    except Exception as e:
        report["sandboxgen"]["error"] = f"no result zip: {e}"
        json.dump(report, open(f"{TASK}/report.json", "w")); return 0

    td = f"{TASK}/task"
    run = {}
    try:
        run = json.load(open(f"{td}/run.json", encoding="utf-8-sig"))
    except Exception:
        pass
    parsed = _parse_sysmon_xml(f"{td}/sysmon.xml")
    procs, files_w, conns, dns, regs, images = parsed if parsed else _parse_sysmon(f"{td}/sysmon.log")
    print(f"sysmon: xml_parsed={bool(parsed)} procs={len(procs)} files={len(files_w)} regs={len(regs)} "
          f"conns={len(conns)} dns={len(dns)} xml_bytes={os.path.getsize(f'{td}/sysmon.xml') if os.path.exists(f'{td}/sysmon.xml') else -1}",
          file=sys.stderr, flush=True)
    sample_name = meta.get("name", "sample.exe")
    tree = _sample_tree(procs, sample_name, meta.get("launch"))
    # Attribute by process tree: Windows background services (ngen, sppsvc, VSS,
    # Edge tasks...) also act inside the capture window; only the sample's own
    # tree counts as behaviour. Legacy text logs carry no pid -> attribute all.
    own = lambda pid: pid in tree
    files_own = sorted({f for pid, f in files_w if own(pid)})
    # certificate-store housekeeping every process does on start (PowerShell
    # alone touches ~100 keys) is not sample behaviour
    _reg_noise = ("\\SystemCertificates\\", "\\EnterpriseCertificates\\", "\\Cryptography\\")
    regs_own = sorted({r for pid, r in regs if own(pid) and not any(n in r for n in _reg_noise)})
    # the guest's own resolver traffic to slirp's DNS is not a sample connection
    _dns_srv = ("10.0.2.3:", "10.0.3.3:", "fec0:0:0:0:0:0:0:3:", "[fec0::3]:")
    conns_own = sorted({c for pid, c in conns if own(pid) and not c.startswith(_dns_srv)})
    dns_own = [{"request": q, "type": "A"} for pid, q in dns if own(pid)]
    pcap_dns, pcap_syns = _parse_pcap(f"{TASK}/net.pcap")
    # the wire view (pcap) shows attempts the isolated guest could not complete;
    # Sysmon event 3 only fires for established flows. Guest-local targets excluded.
    local = ("10.0.2.", "10.0.3.", "127.", "224.", "239.", "255.", "[fe80", "[fec0", "[ff02", "[ff05", "[::")
    syn_ext = [s_ for s_ in pcap_syns if not s_.startswith(local)]
    for q in pcap_dns:
        n = q["request"].lower()
        if n not in [x["request"] for x in dns_own] and not any(n.endswith(x) or n == x.strip(".") for x in _DNS_NOISE):
            dns_own.append(q)
    tree_procs, behavior_summary, background_noise = _shape_attributed_behavior(
        procs, tree, files_own, regs_own, files_w, regs,
    )
    report["behavior"]["processes"] = tree_procs
    report["behavior"]["summary"] = behavior_summary
    all_conns = sorted(set(conns_own) | set(syn_ext))
    report["network"]["hosts"] = sorted({_endpoint_host(c) for c in all_conns})
    report["network"]["tcp"] = [{"dst": c, "established": c in conns_own} for c in all_conns]
    report["network"]["dns"] = dns_own
    # signal: a child process, a write outside the task dir, a registry
    # persistence write, or a network attempt (blocked, but attempted).
    outside = [f for f in files_own if not f.lower().startswith("c:\\task")]
    signal = (len(tree_procs) > 1) or bool(outside) or bool(all_conns) or bool(dns_own) or bool(regs_own)
    conns, dns, regs = all_conns, dns_own, regs_own
    report["malscore"] = 1.0 if signal else 0.0
    if run.get("timed_out"):
        report["signatures"].append({"name": "long_running_or_timeout", "severity": 1})
    # a "timeout" that arrived far earlier than the requested wait means the
    # guest did not actually let the sample run (agent bug, killed launcher...)
    w = run.get("waited_s")
    if run.get("timed_out") and isinstance(w, (int, float)) and w < 0.8 * TIMEOUT:
        report["sandboxgen"]["error"] = f"guest reported timeout after only {w:.0f}s of a {TIMEOUT}s budget"
        print(report["sandboxgen"]["error"], file=sys.stderr, flush=True)
    if outside:
        report["signatures"].append({"name": "writes_outside_workdir", "severity": 2})
    if regs:
        report["signatures"].append({"name": "registry_modification", "severity": 2})
    if conns or dns:
        report["signatures"].append({"name": "network_activity_attempted", "severity": 2})
    lic = []
    try:
        lic = [l.strip() for l in open(f"{td}/license.txt", encoding="utf-8", errors="replace")
               if "License Status" in l or "Notification" in l or "expir" in l.lower() or l.startswith("Name:")]
    except OSError:
        pass
    # update rather than replace: health errors recorded above (for example a
    # guest that claimed a 120 s timeout after only 28 s) must survive in the
    # final report.
    _update_sandboxgen(report, {
        "exit_code": run.get("exit_code"), "timed_out": run.get("timed_out"),
        "killed": run.get("killed"), "export_error": run.get("export_error"),
        "session_id": run.get("session_id"), "launch_error": run.get("launch_error"),
        "guest_timeout_s": run.get("timeout_s"), "guest_waited_s": run.get("waited_s"),
        "wait_error": run.get("wait_error"), "task_result": run.get("task_result"),
        "screenshots": sorted(os.listdir(f"{TASK}/shots")) if os.path.isdir(f"{TASK}/shots") else [],
        "guest_license": lic[:6],
        "process_count": len(tree_procs), "process_tree_pids": sorted(tree),
        "behavior_attribution": "sample_process_tree_only",
        "sample_process_root_found": bool(tree),
        "background_noise_not_sample_behavior": background_noise,
        "duration_s": round(time.time() - started, 1),
        "size_bytes": size, "route_enforced": "drop",
        "launch_executable": run.get("launch_executable"),
        "launch_arguments": run.get("launch_arguments"),
        "launcher_version": run.get("launcher_version"),
    })
    _update_sandboxgen(report, _execution_health(run, tree))
    # dialog-advance keystrokes sent from the host during the run
    report["sandboxgen"]["dialog_keys_sent"] = os.environ.get("DIALOG_KEYS", "ret") if os.environ.get("DRIVE_DIALOGS","1")=="1" else None
    json.dump(report, open(f"{TASK}/report.json", "w"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
