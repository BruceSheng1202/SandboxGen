#!/usr/bin/env python3
"""
Offline unit tests for the qemu backend — no image, no podman, no VM.

The one place a real detonation happens (subprocess.run of `podman run
... detonate.py`) is replaced by a stub that writes the report.json a real
run would produce. Everything else — routing policy, sample typing,
report shaping, sha256 verification, per-task cleanup — is the real code.
The genuine end-to-end run lives in tests/qemu_canary_run.py.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from core.qemu_backend import QemuConfig, QemuCapeClient  # noqa: E402


def _pe_header(*, dll=False, machine=0x8664):
    """Inert header only, never an executable payload."""
    data = bytearray(88)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, machine)
    struct.pack_into("<H", data, 86, 0x2002 if dll else 0x0002)
    return bytes(data)


@pytest.fixture()
def vm_dir(tmp_path: Path) -> Path:
    (tmp_path / "golden.qcow2").write_bytes(b"qcow2-golden")
    return tmp_path


def _client(vm_dir, report):
    cfg = QemuConfig(qemu_vm_dir=str(vm_dir))
    c = QemuCapeClient(cfg, connect=False)
    c._connected = True
    c.podman = "podman"
    c.vm_dir = vm_dir
    c.golden = vm_dir / "golden.qcow2"
    c.task_root = vm_dir / "tasks"; c.task_root.mkdir(exist_ok=True)
    c.win_golden = None; c.win_state = None

    def fake_detonate(task, timeout):
        # what detonate.py would leave behind
        meta = json.load(open(task.dir / "meta.json"))
        r = dict(report)
        r.setdefault("target", {}).setdefault("file", {})["sha256"] = meta["sha256"]
        json.dump(r, open(task.dir / "report.json", "w"))
        task.report = r
        task.status = "reported"
        import os
        for junk in ("sample", "overlay.qcow2"):
            try:
                os.remove(task.dir / junk)
            except OSError:
                pass

    c._detonate = fake_detonate
    return c


_GOOD_REPORT = {
    "info": {"route": "drop"},
    "behavior": {"processes": [{"pid": 1}, {"pid": 2}]},
    "signatures": [{"name": "writes_outside_workdir", "severity": 2}],
    "network": {"dns": [], "tcp": [], "http": [], "hosts": []},
    "malscore": 1.0,
}


def _elf(vm_dir) -> str:
    p = vm_dir / "sample.elf"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00rest")
    return str(p)


def test_elf_detonates_and_reports(vm_dir):
    c = _client(vm_dir, _GOOD_REPORT)
    tid = c.submit_file(_elf(vm_dir), {"route": "drop"})
    assert c.get_task_status(tid) == "reported"
    _, verified, sha = c.get_report_verified(tid, expected_sha256=__import__("hashlib")
                                             .sha256(b"\x7fELF\x02\x01\x01\x00rest").hexdigest())
    assert verified
    sig = c.report_has_signal(c.get_report(tid))
    assert sig["has_signal"] and sig["process_count"] == 2
    assert c.get_task_route(tid) == "drop"


def test_script_is_detonable(vm_dir):
    p = vm_dir / "x.sh"
    p.write_text("#!/bin/sh\necho hi\n")
    c = _client(vm_dir, _GOOD_REPORT)
    assert c.submit_file(str(p), {"route": "drop"}) > 0


def test_windows_pe_refused_without_windows_golden(vm_dir):
    p = vm_dir / "x.exe"
    p.write_bytes(b"MZ\x90\x00stuff")
    c = _client(vm_dir, _GOOD_REPORT)          # no win golden in fixture
    with pytest.raises(ValueError, match="no Windows golden"):
        c.submit_file(str(p), {"route": "drop"})


def _win_client(vm_dir, report):
    (vm_dir / "win-golden.qcow2").write_bytes(b"qcow2-win")
    (vm_dir / "win-state.gz").write_bytes(b"state")
    c = _client(vm_dir, report)
    c.win_golden = vm_dir / "win-golden.qcow2"
    c.win_state = vm_dir / "win-state.gz"
    return c


def test_windows_pe_routes_to_windows_guest(vm_dir):
    import json as _json
    p = vm_dir / "mal.exe"
    p.write_bytes(_pe_header())
    c = _win_client(vm_dir, {**_GOOD_REPORT, "info": {"route": "drop"},
                             "target": {"file": {"sha256": ""}}})
    seen = {}
    real = c._detonate
    def spy(task, timeout):
        seen["os"] = task.guest_os
        real(task, timeout)
    c._detonate = spy
    tid = c.submit_file(str(p), {"route": "drop"})
    assert seen["os"] == "windows"
    meta = _json.load(open(vm_dir / "tasks" / str(tid) / "meta.json"))
    assert meta["os"] == "windows" and meta["name"] == "mal.exe"


def test_windows_backend_lists_windows_machine(vm_dir):
    c = _win_client(vm_dir, _GOOD_REPORT)
    names = [m["name"] for m in c.list_machines()]
    assert "qemu-windows" in names and "qemu-linux" in names


def test_extensionless_pe_gets_exe_name(vm_dir):
    p = vm_dir / "payload"
    p.write_bytes(_pe_header())
    c = _win_client(vm_dir, _GOOD_REPORT)
    def _stub(t, timeout):
        t.report = {}; t.status = "reported"
    c._detonate = _stub
    tid = c.submit_file(str(p), {"route": "drop"})
    import json as _json
    assert _json.load(open(vm_dir / "tasks" / str(tid) / "meta.json"))["name"] == "payload.exe"


def test_network_route_is_refused(vm_dir):
    c = _client(vm_dir, _GOOD_REPORT)
    with pytest.raises(ValueError, match="isolated guest"):
        c.submit_file(_elf(vm_dir), {"route": "internet"})


def test_sample_bytes_removed_after_run(vm_dir):
    c = _client(vm_dir, _GOOD_REPORT)
    tid = c.submit_file(_elf(vm_dir), {"route": "drop"})
    tdir = vm_dir / "tasks" / str(tid)
    assert not (tdir / "sample").exists()
    assert (tdir / "report.json").exists()


def test_cleanup_removes_guest_archives_and_extracted_task(vm_dir):
    """Guest result bundles include the uploaded sample and must not linger."""
    tdir = vm_dir / "tasks" / "1001"
    extracted = tdir / "task"
    extracted.mkdir(parents=True)
    for name in ("sample", "overlay.qcow2", "result.tar.gz", "result.zip"):
        (tdir / name).write_bytes(b"sample bytes")
    (extracted / "original-name.exe").write_bytes(b"sample bytes")
    (tdir / "report.json").write_text("{}")
    shots = tdir / "shots"; shots.mkdir()
    (shots / "000.png").write_bytes(b"png")

    QemuCapeClient._cleanup_task_dir(tdir)

    assert not extracted.exists()
    assert all(not (tdir / name).exists() for name in
               ("sample", "overlay.qcow2", "result.tar.gz", "result.zip"))
    assert (tdir / "report.json").exists()
    assert (shots / "000.png").exists()


def test_route_readback_matches_enforced_policy(vm_dir):
    # SG-NET-01: the backend enforces the route, so it reports it back and the
    # ledger confirmation in the orchestrator will pass.
    c = _client(vm_dir, _GOOD_REPORT)
    tid = c.submit_file(_elf(vm_dir), {"route": "drop"})
    assert c.get_task_route(tid) == "drop"


def test_missing_golden_refuses_to_connect(tmp_path):
    c = QemuCapeClient(QemuConfig(qemu_vm_dir=str(tmp_path)), connect=False)
    with pytest.raises(RuntimeError, match="golden image not found"):
        c.connect()


@pytest.mark.parametrize("name", ["payload.47428979", "Order no. 274419.exe", "payload", "payload.py", "payload.sh"])
def test_pe_executable_transport_name(vm_dir, name):
    p = vm_dir / name; p.write_bytes(_pe_header())
    c = _win_client(vm_dir, _GOOD_REPORT)
    tid = c.submit_file(str(p), {"package": "exe"})
    meta = json.loads((vm_dir / "tasks" / str(tid) / "meta.json").read_text())
    assert meta["name"] == (name if name.endswith(".exe") else name + ".exe")
    assert meta["launch"]["package"] == "exe"


@pytest.mark.parametrize("machine,arch", [(0x14c, "x86"), (0x8664, "x64")])
@pytest.mark.parametrize("entry", ["TestEntry", "#12"])
def test_dll_export_and_arch_reach_runner(vm_dir, machine, arch, entry):
    p = vm_dir / "test.dll"; p.write_bytes(_pe_header(dll=True, machine=machine))
    c = _win_client(vm_dir, _GOOD_REPORT)
    tid = c.submit_file(str(p), {"package": "dll", "options": f"function={entry}"})
    meta = json.loads((vm_dir / "tasks" / str(tid) / "meta.json").read_text())
    assert meta["name"] == "test.dll"
    assert meta["launch"]["function"] == entry
    assert meta["launch"]["architecture"] == arch


@pytest.mark.parametrize("options", ["", "function=DllMain", "function=", "function=#0",
    "function=#65536", 'function=Test\" & whoami', "function=One,function=Two"])
def test_bad_dll_entry_refused_before_staging(vm_dir, options):
    p = vm_dir / "test.dll"; p.write_bytes(_pe_header(dll=True))
    c = _win_client(vm_dir, _GOOD_REPORT)
    with pytest.raises(ValueError):
        c.submit_file(str(p), {"package": "dll", "options": options})
    assert not c._tasks and not list(c.task_root.iterdir())


@pytest.mark.parametrize("dll,package", [(True, "exe"), (False, "dll"), (False, "doc")])
def test_wrong_package_not_silently_corrected(vm_dir, dll, package):
    p = vm_dir / "sample.bin"; p.write_bytes(_pe_header(dll=dll))
    c = _win_client(vm_dir, _GOOD_REPORT)
    with pytest.raises(ValueError, match="PACKAGE|package"):
        c.submit_file(str(p), {"package": package, "options": "function=Test"})
    assert not c._tasks


@pytest.mark.parametrize("data", [b"MZshort", _pe_header(machine=0xaa64),
    b"MZ" + b"\0" * 58 + b"\xff" * 4])
def test_invalid_or_unsupported_pe_refused(vm_dir, data):
    p = vm_dir / "sample.exe"; p.write_bytes(data)
    c = _win_client(vm_dir, _GOOD_REPORT)
    with pytest.raises(ValueError):
        c.submit_file(str(p), {"package": "exe"})
    assert not c._tasks


def test_unimplemented_cape_options_reported(vm_dir):
    p = vm_dir / "test.dll"; p.write_bytes(_pe_header(dll=True))
    c = _win_client(vm_dir, _GOOD_REPORT)
    tid = c.submit_file(str(p), {"package": "dll", "memory": True,
        "options": "function=Test,force-sleepskip=1,injection=1"})
    assert c.submission_warnings(tid) == ["force-sleepskip=1", "injection=1", "memory=True"]


@pytest.mark.parametrize("image,health", [
    (None, {}),
    (r"C:\Windows\System32\OpenWith.exe", {"sample_process_root_found": True}),
    (r"C:\task\sample.exe", {"sample_process_root_found": True, "launch_error": "failed"}),
    (r"C:\task\sample.exe", {"sample_process_root_found": True, "wait_error": "null"}),
    (r"C:\task\sample.exe", {"sample_process_root_found": True, "export_error": "failed"}),
    (r"C:\task\sample.exe", {"sample_process_root_found": True, "execution_valid": False}),
])
def test_invalid_windows_execution_never_has_signal(vm_dir, image, health):
    report = {**_GOOD_REPORT, "backend": "qemu-tcg-windows", "sandboxgen": health,
              "behavior": {"processes": [{"image": image}] if image else []}}
    quality = _client(vm_dir, {}).report_has_signal(report)
    assert quality["has_signal"] is False
    assert quality["execution_valid"] is False


def test_windows_timeout_with_real_execution_is_valid(vm_dir):
    report = {**_GOOD_REPORT, "backend": "qemu-tcg-windows",
        "target": {"file": {"name": "sample.exe"}},
        "sandboxgen": {"sample_process_root_found": True, "timed_out": True, "execution_valid": True},
        "behavior": {"processes": [{"image": r"C:\task\sample.exe"}]}}
    assert _client(vm_dir, {}).report_has_signal(report)["has_signal"] is True


@pytest.mark.parametrize("name", ["NUL.exe", "CON.dll", "bad%name.exe", 'bad"name.exe'])
def test_unsafe_windows_filename_refused(vm_dir, name):
    p = vm_dir / name; p.write_bytes(_pe_header())
    c = _win_client(vm_dir, _GOOD_REPORT)
    with pytest.raises(ValueError, match="filename"):
        c.submit_file(str(p), {"package": "exe"})


def test_loader_without_dll_image_load_is_invalid(vm_dir):
    report = {**_GOOD_REPORT, "backend": "qemu-tcg-windows",
        "target": {"file": {"name": "sample.dll"}}, "info": {"package": "dll"},
        "sandboxgen": {"sample_process_root_found": True},
        "behavior": {"processes": [{"image": r"C:\Windows\System32\rundll32.exe"}]}}
    c = _client(vm_dir, {})
    assert c.report_has_signal(report)["has_signal"] is False
    report["behavior"]["processes"][0]["loaded_images"] = [r"C:\task\sample.dll"]
    assert c.report_has_signal(report)["has_signal"] is True
