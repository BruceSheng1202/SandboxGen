#!/usr/bin/env python3
"""
core/qemu_backend.py — a KVM-free Linux dynamic-analysis backend that speaks
the same client interface as CAPEClient.

Why this exists: the cluster has no usable KVM (/dev/kvm is group-empty) and
no host root for libvirt, so real CAPEv2 cannot run here (internal work log, 2026-09-06).
This backend detonates an ELF/script sample inside a qemu (TCG) Linux VM run
under rootless podman with no network, and returns a CAPE-shaped report, so
the whole pipeline above it is unchanged.

Isolation, four walls (see sandbox_infra/qemu/README.md): container
`--network none --cap-drop=ALL --read-only`; qemu system emulation; guest
`-netdev user,restrict=on`; per-task `-drive snapshot=on` discard overlay.

Only the isolated route is offered. A run that asks for network egress is
refused rather than run without the isolation the caller expected.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import logging

logger = logging.getLogger("amsa")

_ROUTE = "drop"                      # the only route this backend enforces
_ELF_MAGIC = b"\x7fELF"
_SCRIPT_INTERPRETERS = {
    ".sh": "/bin/sh", ".py": "/usr/bin/python3", ".pl": "/usr/bin/perl",
}


@dataclass
class QemuConfig:
    mode: str = "qemu"
    qemu_image: str = "localhost/sandboxgen-qemu:alpine3.20"
    qemu_vm_dir: str = ""            # holds golden.qcow2 (persistent, NFS ok)
    qemu_golden: str = "golden.qcow2"
    # Where per-task overlays and sample bytes live: local scratch, ephemeral
    # by design, never NFS (DATA-04). Falls back to <vm_dir>/tasks if unset.
    qemu_task_dir: str = ""
    # Windows backend (optional): golden + external RAM savestate. When both
    # are present, PE samples are detonated in the Windows guest; otherwise a
    # PE is refused (Linux-only deployment).
    qemu_win_golden: str = "win-golden.qcow2"
    qemu_win_state: str = "win-state.gz"
    qemu_win_smp: int = 8          # must equal the -smp the Windows RAM state was saved with
    # Command used to reach a container engine. On the host this is "podman";
    # inside the harness container it is "podman-remote --url unix:///run/podman/
    # podman.sock" so detonation containers are spawned as SIBLINGS on the host
    # (keeping their own --network none), not nested. A space-separated string;
    # overridable with the SANDBOXGEN_PODMAN env var.
    podman_bin: str = ""
    timeout: int = 120               # in-guest run timeout
    mem_mb: int = 1536
    smp: int = 4
    container_timeout: int = 1200    # hard cap on the whole detonation
    # Kept for interface parity with CAPEConfig (Executor reads cfg.storage).
    storage: str = ""
    container: str = ""
    url: str = ""
    token: str = ""

    @classmethod
    def from_yaml(cls, path: str) -> "QemuConfig":
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        cfg = cls()
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


@dataclass
class _Task:
    task_id: int
    dir: Path
    report: Optional[dict] = None
    status: str = "pending"
    guest_os: str = "linux"
    warnings: list[str] = field(default_factory=list)


class QemuCapeClient:
    """
    Synchronous detonation behind the CAPEClient method surface.

    submit_file() runs the whole analysis (boot, detonate, collect) and only
    then returns the task id. get_task_status() reports the terminal outcome
    (including failures), and get_report() returns available shaped evidence. This matches how the Executor
    uses the client and keeps the ledger/route-confirmation wiring intact.
    """

    def __init__(self, cfg: QemuConfig, *, connect: bool = True):
        self.cfg = cfg
        self._tasks: dict[int, _Task] = {}
        self._next = 1000
        self._connected = False
        if connect:
            self.connect()

    # ── lifecycle ──────────────────────────────────────────────────────────

    def connect(self) -> None:
        if self._connected:
            return
        podman = (os.environ.get("SANDBOXGEN_PODMAN")
                  or self.cfg.podman_bin
                  or shutil.which("podman") or "podman")
        self.podman = podman.split()          # may carry --url ...
        chk0 = self.podman
        vm_dir = Path(self.cfg.qemu_vm_dir or "")
        golden = vm_dir / self.cfg.qemu_golden
        if not golden.is_file():
            raise RuntimeError(
                f"qemu golden image not found at {golden}. Build it first: "
                f"sandbox_infra/qemu/build_guest.sh")
        if subprocess.run([*self.podman, "image", "exists", self.cfg.qemu_image]).returncode != 0:
            # The scratch-backed podman store reclaims layers on a TTL, so an
            # image can vanish mid-campaign. Restore it from the persistent NFS
            # tarball before giving up (SANDBOXGEN_IMAGE_STORE, default
            # vmstore/images/) — self-healing so a long batch does not die when
            # the reaper runs.
            store = os.environ.get("SANDBOXGEN_IMAGE_STORE",
                                   str(Path.home() / "sandboxgen" / "vmstore" / "images"))
            tar = Path(store) / "sandboxgen-qemu.tar"
            if tar.is_file():
                logger.warning("[QemuBackend] image missing; restoring from %s", tar)
                subprocess.run([*self.podman, "load", "-i", str(tar)], check=True,
                               stdout=subprocess.DEVNULL)
            if subprocess.run([*self.podman, "image", "exists", self.cfg.qemu_image]).returncode != 0:
                raise RuntimeError(
                    f"qemu runner image {self.cfg.qemu_image!r} not found and no tarball "
                    f"at {tar}. Build it: podman build -t {self.cfg.qemu_image} sandbox_infra/qemu")
        self.vm_dir = vm_dir
        self.golden = golden
        wg = vm_dir / self.cfg.qemu_win_golden
        ws = vm_dir / self.cfg.qemu_win_state
        self.win_golden = wg if (wg.is_file() and ws.is_file()) else None
        self.win_state = ws if self.win_golden else None
        self.task_root = Path(self.cfg.qemu_task_dir) if self.cfg.qemu_task_dir \
                         else vm_dir / "tasks"
        self.task_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.task_root, 0o700)
        self._connected = True
        logger.info("[QemuBackend] ready: image=%s golden=%s", self.cfg.qemu_image, golden)

    # ── submit ─────────────────────────────────────────────────────────────

    def _detect(self, sample_path: str, options: dict) -> tuple[str, str, Optional[str]]:
        """(os, name, interpreter). Refuse what no configured guest can run."""
        p = Path(sample_path)
        head = b""
        try:
            head = open(sample_path, "rb").read(2)
        except OSError:
            pass
        interp = _SCRIPT_INTERPRETERS.get(p.suffix.lower())
        if head == _ELF_MAGIC[:2] or (interp and head != b"MZ"):
            return "linux", p.name, interp
        if head == b"MZ" or p.suffix.lower() in (".exe", ".dll"):
            if self.win_golden is not None:
                # Windows ShellExecute treats unknown suffixes as documents.
                # Keep the original basename, but make EXE transport explicit.
                suffix = ".dll" if options.get("package") == "dll" else ".exe"
                name = p.name if p.suffix.lower() == suffix else p.name + suffix
                return "windows", name, None
            raise ValueError(
                f"{p.name} is a Windows PE but no Windows golden is built "
                f"(qemu_win_golden/{self.cfg.qemu_win_state}); refusing.")
        raise ValueError(
            f"qemu backend cannot detonate {p.name} (magic={head!r}); "
                f"supported: ELF, script (.sh/.py/.pl), Windows PE.")

    @staticmethod
    def _windows_launch(sample_path: str, name: str, options: dict) -> dict:
        """Validate a bounded PE header and the caller's explicit launch choice.

        This does not guess a DLL export or change the caller's package. No
        sample-controlled strings become host commands.
        """
        if (re.search(r'[<>:"/\\|?*%\x00-\x1f]', name) or len(name) > 200
                or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", name.split('.')[0], re.I)
                or name.lower() in {"run-sample.ps1", "launch-request.json"}):
            raise ValueError("unsupported Windows sample filename")
        with open(sample_path, "rb") as f:
            dos = f.read(64)
            if len(dos) != 64 or dos[:2] != b"MZ":
                raise ValueError("invalid PE: missing DOS header")
            offset = struct.unpack_from("<I", dos, 60)[0]
            if not 64 <= offset <= 1024 * 1024:
                raise ValueError("invalid PE: header offset outside supported bounds")
            f.seek(offset)
            pe = f.read(24)
        if len(pe) != 24 or pe[:4] != b"PE\0\0":
            raise ValueError("invalid PE: missing COFF header")
        machine = struct.unpack_from("<H", pe, 4)[0]
        arch = {0x14c: "x86", 0x8664: "x64"}.get(machine)
        if arch is None:
            raise ValueError("unsupported PE architecture: Windows guest supports x86/x64")
        is_dll = bool(struct.unpack_from("<H", pe, 22)[0] & 0x2000)
        package = options.get("package") or "exe"
        if package not in ("exe", "dll"):
            raise ValueError(f"unsupported Windows package {package!r}; supported: exe, dll")
        if (package == "dll") != is_dll:
            raise ValueError(f"WRONG_PACKAGE: package={package} does not match PE DLL flag={is_dll}")
        tokens = {}
        for token in (options.get("options") or "").split(","):
            if not token.strip():
                continue
            key, _, value = token.strip().partition("=")
            if key in tokens:
                raise ValueError(f"duplicate submission option: {key}")
            tokens[key] = value
        function = tokens.pop("function", None)
        if package == "dll":
            if not function or not re.fullmatch(r"(?:[A-Za-z_?@$][A-Za-z0-9_?@$]*|#[1-9][0-9]{0,4})", function):
                raise ValueError("DLL requires an explicit function=<export name or #ordinal>; no entry is guessed")
            if function.lower() == "dllmain":
                raise ValueError("DllMain is not a rundll32 export; choose an exported function explicitly")
            if function.startswith("#") and int(function[1:]) > 65535:
                raise ValueError("DLL export ordinal must be <= 65535")
        elif function is not None:
            raise ValueError("function= is only supported with package=dll")
        # CAPE options are not implemented by the Sysmon/TCG backend. Preserve
        # and surface them; never present them as applied anti-evasion features.
        unsupported = [f"{k}={v}" for k, v in tokens.items()]
        for key in ("memory", "tags", "priority"):
            if options.get(key):
                unsupported.append(f"{key}={options[key]}")
        if options.get("machine") not in (None, "", "qemu-windows"):
            unsupported.append(f"machine={options['machine']} (actual: qemu-windows)")
        if options.get("platform") not in (None, "", "windows"):
            unsupported.append(f"platform={options['platform']} (actual: windows)")
        if options.get("enforce_timeout") is False:
            unsupported.append("enforce_timeout=False (full observation window is always enforced)")
        return {"version": 1, "package": package, "architecture": arch,
                "function": function, "unsupported_options": unsupported}

    def submit_file(self, sample_path: str, options: dict = None) -> int:
        if not self._connected:
            self.connect()
        options = options or {}
        route = options.get("route", _ROUTE)
        if route not in (_ROUTE, "none"):
            raise ValueError(
                f"qemu backend enforces an isolated guest (route={_ROUTE}); it cannot "
                f"honour route={route!r}. Refusing rather than running without the "
                f"isolation the network policy asked for.")
        guest_os, name, interp = self._detect(sample_path, options)
        timeout = int(options.get("timeout") or self.cfg.timeout)
        if not 1 <= timeout <= 1800:
            raise ValueError("analysis timeout must be between 1 and 1800 seconds")
        launch = self._windows_launch(sample_path, name, options) if guest_os == "windows" else None
        if launch and launch["unsupported_options"]:
            logger.warning("[QemuBackend] options not applied: %s", launch["unsupported_options"])

        self._next += 1
        task_id = self._next
        # Per-task dir on local scratch (never NFS): the sample bytes live here
        # 0700 and are removed after the run; the golden it is backed by can be
        # on NFS (read-only) without the samples touching NFS.
        tdir = self.task_root / str(task_id)
        tdir.mkdir(parents=True, exist_ok=True)
        os.chmod(tdir, 0o700)
        shutil.copyfile(sample_path, tdir / "sample")
        os.chmod(tdir / "sample", 0o600)
        import hashlib
        sha = hashlib.sha256(open(tdir / "sample", "rb").read()).hexdigest()
        json.dump({"sha256": sha, "name": name, "original_name": Path(sample_path).name,
                   "interpreter": interp, "os": guest_os,
                   "package": launch["package"] if launch else options.get("package"),
                   "launch": launch, "timeout": timeout},
                  open(tdir / "meta.json", "w"))

        task = _Task(task_id=task_id, dir=tdir)
        task.guest_os = guest_os
        task.warnings = launch["unsupported_options"] if launch else []
        self._tasks[task_id] = task
        self._detonate(task, timeout=timeout)
        return task_id

    def _detonate(self, task: _Task, timeout: int) -> None:
        here = Path(__file__).resolve().parent.parent / "sandbox_infra" / "qemu"
        common = [
            *self.podman, "run", "--rm",
            "--network", "none",                 # wall 1: no network device
            "--read-only", "--tmpfs", "/tmp:rw,size=2g,exec",
            "--cap-drop=ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "1024",
            "-v", f"{task.dir}:/task:rw",
            "-e", f"TIMEOUT={timeout}", "-e", f"SMP={self.cfg.smp}",
            "-e", "TASK_DIR=/task",
        ]
        if task.guest_os == "windows":
            argv = common + [
                "--memory", "10g",
                "-v", f"{self.win_golden}:/vm/win-golden.qcow2:ro",
                "-v", f"{self.win_state}:/vm/win-state.gz:ro",
                "-v", f"{here}/win_detonate.py:/win_detonate.py:ro",
                "-v", f"{here}/windows/run-sample.ps1:/run-sample.ps1:ro",
                # later -e wins: the Windows state was saved with its own smp,
                # not the Linux guest's cfg.smp
                "-e", f"SMP={self.cfg.qemu_win_smp}",
                "-e", "MEM_MB=4096", "-e", "GOLDEN=/vm/win-golden.qcow2",
                "-e", "STATE=/vm/win-state.gz",
                self.cfg.qemu_image, "python3", "/win_detonate.py",
            ]
        else:
            argv = common + [
                "--memory", "6g",
                "-v", f"{self.golden}:/vm/golden.qcow2:ro",
                "-v", f"{here}/detonate.py:/detonate.py:ro",
                "-e", f"MEM_MB={self.cfg.mem_mb}", "-e", "GOLDEN=/vm/golden.qcow2",
                self.cfg.qemu_image, "python3", "/detonate.py",
            ]
        logger.info("[QemuBackend] detonating task %d (timeout=%ds)", task.task_id, timeout)
        try:
            try:
                completed = subprocess.run(
                    argv, timeout=self.cfg.container_timeout,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                if completed.returncode != 0:
                    raw_detail = completed.stderr or b""
                    detail = (raw_detail.decode(errors="replace") if isinstance(raw_detail, bytes)
                              else str(raw_detail))[-2000:]
                    logger.error("[QemuBackend] task %d runner exited %d: %s",
                                 task.task_id, completed.returncode, detail)
            except subprocess.TimeoutExpired:
                logger.error("[QemuBackend] task %d exceeded container timeout", task.task_id)
            report_path = task.dir / "report.json"
            if report_path.is_file():
                task.report = json.load(open(report_path))
                task.status = "reported"
            else:
                task.report = {"target": {"file": {"sha256": ""}},
                               "sandboxgen": {"error": "detonation produced no report"},
                               "behavior": {"processes": []}, "signatures": [],
                               "network": {"dns": [], "tcp": [], "http": [], "hosts": []},
                               "malscore": 0.0}
                task.status = "failed_analysis"
        finally:
            self._cleanup_task_dir(task.dir)

    @staticmethod
    def _cleanup_task_dir(task_dir: Path) -> None:
        """Remove every local artefact that can still contain sample bytes.

        Both guest agents return their whole task directory, including the
        uploaded executable, in ``result.tar.gz``/``result.zip``.  Removing
        only the host-side ``sample`` therefore left two extra copies behind:
        one in the archive and one in the extracted ``task/`` directory.
        Reports and screenshots have already been shaped outside ``task/`` and
        remain available for debugging.
        """
        for junk in ("sample", "overlay.qcow2", "result.tar.gz", "result.zip"):
            try:
                os.remove(task_dir / junk)
            except OSError:
                pass
        shutil.rmtree(task_dir / "task", ignore_errors=True)

    # ── query (CAPEClient parity) ──────────────────────────────────────────

    def get_task_status(self, task_id: int) -> str:
        t = self._tasks.get(int(task_id))
        return t.status if t else "not_found"

    def submission_warnings(self, task_id: int) -> list[str]:
        return list(self._tasks[int(task_id)].warnings)

    def capabilities(self) -> dict:
        return {"backend": "qemu-tcg", "windows_packages": ["exe", "dll"],
                "windows_options": ["function"], "routes": ["drop", "none"],
                "dll_loader": "rundll32; explicit compatible export name/#ordinal required; DllMain unsupported",
                "memory_dump": False, "cape_monitor_options": False,
                "vm_provisioning": False,
                "note": "CAPE sleep skipping, extraction and injection options are not implemented. "
                        "Do not claim these features are applied. DLL ImageLoad proves loading, "
                        "not successful invocation of the selected export."}

    def get_report(self, task_id: int) -> dict:
        t = self._tasks.get(int(task_id))
        if not t or t.report is None:
            raise FileNotFoundError(f"no report for task {task_id}")
        return t.report

    def get_report_verified(self, task_id: int, expected_sha256: str = None):
        report = self.get_report(task_id)
        seen = (report.get("target", {}).get("file", {}).get("sha256")
                or report.get("target", {}).get("sha256") or "")
        verified = bool(expected_sha256) and seen.strip().lower() == expected_sha256.strip().lower()
        return report, verified, seen

    def report_has_signal(self, report: dict) -> dict:
        procs = len((report.get("behavior") or {}).get("processes") or [])
        sigs = len(report.get("signatures") or [])
        net = report.get("network") or {}
        net_events = sum(len(net.get(k) or []) for k in ("dns", "tcp", "http", "hosts"))
        malscore = report.get("malscore", 0) or 0
        health = report.get("sandboxgen") or {}
        execution_valid = None
        if report.get("backend") == "qemu-tcg-windows":
            # Recheck old reports too: old collectors called OpenWith a sample
            # root and allowed timeout signatures to hide a failed launch.
            processes = (report.get("behavior") or {}).get("processes") or []
            name = ((report.get("target") or {}).get("file") or {}).get("name")
            expected = f"c:\\task\\{name}".lower() if name else None
            if (report.get("info") or {}).get("package") == "dll":
                real = [p for p in processes if str(p.get("image", "")).lower() in
                        ("c:\\windows\\system32\\rundll32.exe", "c:\\windows\\syswow64\\rundll32.exe")
                        and expected in [i.lower() for i in p.get("loaded_images", [])]]
            else:
                real = [p for p in processes if expected and str(p.get("image", "")).lower() == expected]
            execution_valid = bool(real) and health.get("sample_process_root_found") is True
            execution_valid = execution_valid and not any(health.get(k) for k in
                ("error", "launch_error", "wait_error", "export_error"))
            if health.get("execution_valid") is False:
                execution_valid = False
        return {"process_count": procs, "signature_count": sigs,
                "malscore": malscore, "network_events": net_events,
                "execution_valid": execution_valid,
                "has_signal": execution_valid is not False and bool(procs or sigs or malscore > 0 or net_events)}

    def get_task_route(self, task_id: int) -> Optional[str]:
        # The backend enforces the route itself (restrict=on), so it can report
        # authoritatively what every task ran under.
        t = self._tasks.get(int(task_id))
        if not t or t.report is None:
            return None
        return (t.report.get("info") or {}).get("route", _ROUTE)

    def supported_routes(self) -> set:
        # --network none + restrict=on can only isolate; no inetsim/internet.
        return {"drop", "none"}

    def list_machines(self) -> list:
        m = [{"name": "qemu-linux", "platform": "linux", "arch": "x86_64",
              "tags": "qemu,tcg,isolated"}]
        if getattr(self, "win_golden", None) is not None:
            m.append({"name": "qemu-windows", "platform": "windows", "arch": "x86_64",
                      "tags": "qemu,tcg,isolated,windows"})
        return m


def build_qemu_client(config_path: str = None, *, connect: bool = False) -> QemuCapeClient:
    cfg = QemuConfig.from_yaml(config_path) if config_path else QemuConfig()
    return QemuCapeClient(cfg, connect=connect)
