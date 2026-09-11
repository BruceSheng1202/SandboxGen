#!/usr/bin/env python3
"""
Real end-to-end detonation of the harmless canary through the qemu backend.
NOT part of the pytest suite (slow, needs the golden image + podman). Run
manually to validate the backend before any real sample:

    .venv/bin/python tests/qemu_canary_run.py
"""
import json, os, sys
from pathlib import Path
SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
from core.qemu_backend import QemuConfig, QemuCapeClient

vm_dir = os.environ.get("SANDBOXGEN_VM_DIR", f"/scratch/{os.environ.get('USER','root')}/sandboxgen-vm")
canary = SRC / "sandbox_infra" / "qemu" / "canary.sh"

cfg = QemuConfig(qemu_vm_dir=vm_dir, timeout=45)
client = QemuCapeClient(cfg, connect=True)
print(f"detonating canary {canary} ...")
tid = client.submit_file(str(canary), {"route": "drop", "package": "sh"})
print("task_id:", tid, "status:", client.get_task_status(tid))
report = client.get_report(tid)
sig = client.report_has_signal(report)
sg = report.get("sandboxgen", {})
print("signal:", json.dumps(sig))
print("route:", client.get_task_route(tid))
print("exit_code:", sg.get("exit_code"), "syscalls:", sg.get("syscalls"),
      "procs:", sg.get("process_count"), "duration_s:", sg.get("duration_s"))
print("signatures:", [s["name"] for s in report.get("signatures", [])])
print("modified_files (sample):", [f for f in sg.get("modified_files", []) if "canary" in f][:5])
print("network hosts:", report.get("network", {}).get("hosts"))
ok = sig["has_signal"] and client.get_task_route(tid) == "drop" and sg.get("process_count", 0) >= 1
print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
