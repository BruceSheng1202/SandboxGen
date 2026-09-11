#!/usr/bin/env python3
"""
SandboxGEN in-guest agent (Linux, qemu backend).

A tiny HTTP server on 0.0.0.0:8000 inside the analysis VM, reached by the
task driver through qemu's hostfwd. It stores one sample, runs it under
strace with tcpdump capturing, and hands the artefacts back as a tarball.

Endpoints:
  GET  /status                 -> {"status": "ready", ...}
  POST /store?name=<n>         body = file bytes    -> {"path", "sha256", "size"}
  POST /execute                json {"path", "timeout", "args": [], "interpreter": null}
  GET  /poll                   -> {"state": "idle"|"running"|"done", ...}
  GET  /result                 -> application/gzip tarball of the task dir
  POST /shutdown               -> poweroff (used by the image builder)

Everything runs as root inside a disposable guest that is discarded after
the task; nothing here is a security boundary, the VM is.
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

TASK_DIR = "/tmp/task"
STATE = {"state": "idle", "started": None, "pid": None, "timeout": None}
_LOCK = threading.Lock()


def _json(handler, code, obj):
    body = json.dumps(obj).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _snapshot_files():
    """Paths modified after the marker: candidate dropped/modified files."""
    out = []
    try:
        r = subprocess.run(
            ["find", "/", "-xdev", "-newer", f"{TASK_DIR}/.marker", "-type", "f",
             "-not", "-path", f"{TASK_DIR}/*", "-not", "-path", "/proc/*",
             "-not", "-path", "/sys/*", "-not", "-path", "/run/*",
             "-not", "-path", "/var/log/*", "-not", "-path", "/dev/*"],
            capture_output=True, text=True, timeout=60)
        out = [l for l in r.stdout.splitlines() if l][:2000]
    except Exception:
        pass
    return out


def _run_task(path, timeout, args, interpreter):
    os.makedirs(TASK_DIR, exist_ok=True)
    open(f"{TASK_DIR}/.marker", "w").close()
    os.chmod(path, 0o755)
    pcap = subprocess.Popen(
        ["tcpdump", "-i", "any", "-nn", "-U", "-s", "0", "-w", f"{TASK_DIR}/net.pcap"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    cmd = [interpreter, path] if interpreter else [path]
    cmd += list(args or [])
    strace = ["strace", "-f", "-ttt", "-yy", "-s", "256", "-o", f"{TASK_DIR}/strace.log",
              "-e", "trace=all", "--"] + cmd
    with open(f"{TASK_DIR}/stdout.txt", "wb") as so, open(f"{TASK_DIR}/stderr.txt", "wb") as se:
        proc = subprocess.Popen(strace, stdout=so, stderr=se, cwd="/root",
                                start_new_session=True)
        with _LOCK:
            STATE.update(state="running", started=time.time(), pid=proc.pid, timeout=timeout)
        try:
            proc.wait(timeout=timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            exit_code = None
    # Let children finish their last syscalls, then freeze everything spawned.
    time.sleep(2)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        pass
    subprocess.run(["sh", "-c", "ps -eo pid,ppid,user,etimes,comm,args > %s/ps.txt" % TASK_DIR],
                   timeout=20)
    time.sleep(1)
    pcap.send_signal(signal.SIGINT)
    try:
        pcap.wait(timeout=10)
    except Exception:
        pcap.kill()
    json.dump({"exit_code": exit_code, "timed_out": exit_code is None,
               "modified_files": _snapshot_files(),
               "cmd": cmd, "duration_s": time.time() - STATE["started"]},
              open(f"{TASK_DIR}/run.json", "w"))
    with _LOCK:
        STATE.update(state="done")


class Handler(BaseHTTPRequestHandler):
    server_version = "SandboxGEN-agent/1.0"

    def log_message(self, *a):   # quiet
        pass

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/status":
            _json(self, 200, {"status": "ready", "hostname": os.uname().nodename,
                              "kernel": os.uname().release, "state": STATE["state"]})
        elif u.path == "/poll":
            with _LOCK:
                _json(self, 200, dict(STATE))
        elif u.path == "/result":
            if STATE["state"] != "done":
                return _json(self, 409, {"error": "no finished task"})
            tmp = "/tmp/result.tar.gz"
            with tarfile.open(tmp, "w:gz") as tf:
                tf.add(TASK_DIR, arcname="task")
            data = open(tmp, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            _json(self, 404, {"error": "unknown"})

    def do_POST(self):
        u = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        if u.path == "/store":
            name = parse_qs(u.query).get("name", ["sample"])[0]
            name = os.path.basename(name) or "sample"
            os.makedirs(TASK_DIR, exist_ok=True)
            path = f"{TASK_DIR}/{name}"
            with open(path, "wb") as f:
                f.write(body)
            _json(self, 200, {"path": path, "sha256": hashlib.sha256(body).hexdigest(),
                              "size": len(body)})
        elif u.path == "/execute":
            try:
                req = json.loads(body or b"{}")
            except Exception:
                return _json(self, 400, {"error": "bad json"})
            if STATE["state"] == "running":
                return _json(self, 409, {"error": "busy"})
            path = req.get("path")
            if not path or not os.path.isfile(path):
                return _json(self, 400, {"error": "path missing"})
            t = threading.Thread(target=_run_task,
                                 args=(path, int(req.get("timeout", 60)),
                                       req.get("args") or [], req.get("interpreter")),
                                 daemon=True)
            t.start()
            _json(self, 200, {"ok": True})
        elif u.path == "/shutdown":
            _json(self, 200, {"ok": True})
            threading.Thread(target=lambda: (time.sleep(1), subprocess.run(["poweroff"])),
                             daemon=True).start()
        else:
            _json(self, 404, {"error": "unknown"})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
