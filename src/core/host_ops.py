#!/usr/bin/env python3
"""
core/host_ops.py — typed, argv-only operations against the CAPE host

SG-CTL-01 remediation. Replaces `ExecutorAgent._shell()`.

The old helper took a command string and ran it through
`subprocess.run(..., shell=True)`. Every recovery action built that string by
interpolating values — the worst being CAPE task IDs, which an agent could set
via `update_spec` — so the shell metacharacter boundary did not exist. The
audit requires removing `ExecutorAgent._shell()`, using fixed argv with
`shell=False`, and keeping task IDs as positive integers only in the
controller's private run state.

This module is the fixed-argv surface that replaces it:

  * nothing takes a command string; every operation is a named method whose
    arguments are typed and validated;
  * there is no `bash -c` anywhere, so shell grammar is not in play at all —
    `|| true` and `&& echo UP` are gone, replaced by inspecting the exit code
    in Python, which is what those constructs were emulating;
  * VM names come from an allowlist, not from a caller-supplied string;
  * every VM-mutating operation requires the run to hold a lease on that VM
    (SG-CONC-01), so two runs cannot destroy each other's machine;
  * task IDs are `int` in the signature and are re-checked against the run
    ledger before use, so an ID this run did not submit cannot be reached
    (SG-AUTH-01).

What this module does *not* do is make VM and container control safe. The
Orchestrator still needs Docker and libvirt reach to call any of it, which is
SG-INF-01 and P0-3's least-privilege CAPE broker. This closes the injection
boundary; it does not shrink the blast radius.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence

from core.run_context import RunContext

# Analysis VMs this harness is allowed to name. A value outside the set is a
# programming error, not something to pass through to libvirt.
ALLOWED_VMS: frozenset[str] = frozenset({"cuckoo1", "cuckoo2_linux"})

# Snapshots the start scripts actually create. Round-1 INF-08 was a mismatch
# between the name the recovery path used and the name the start script made;
# pinning the set here means a drift shows up as a refusal, not a silent
# "revert failed" that the correction loop reports as attempted.
ALLOWED_SNAPSHOTS: frozenset[str] = frozenset({"agent_ready"})

CAPE_SERVICES: tuple[str, ...] = (
    "cape.service",
    "cape-web.service",
    "cape-processor.service",
)

# Cap on captured output. SG-RES-01: a command whose output is unbounded can
# exhaust memory before any timeout fires.
MAX_CAPTURE_BYTES = 1024 * 1024


class HostOpError(Exception):
    """An operation was refused before it ran."""


@dataclass(frozen=True)
class CommandResult:
    """What a host operation returned. `ok` never guesses — it reads the code."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def combined(self) -> str:
        return (self.stdout + self.stderr).strip()


def _run(argv: Sequence[str], timeout: int) -> CommandResult:
    """
    The single place this module starts a process.

    `shell=False` is passed explicitly rather than relied on as the default:
    the static gate in the security tests asserts that every `subprocess`
    call in the tree carries a literal `shell=False`, so the property is
    checkable without reasoning about defaults.
    """
    argv = [str(a) for a in argv]
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            argv=tuple(argv),
            returncode=124,
            stdout=(e.stdout or "")[:MAX_CAPTURE_BYTES] if isinstance(e.stdout, str) else "",
            stderr=f"timed out after {timeout}s",
            timed_out=True,
        )
    except FileNotFoundError as e:
        return CommandResult(
            argv=tuple(argv), returncode=127, stdout="", stderr=str(e)
        )
    return CommandResult(
        argv=tuple(argv),
        returncode=proc.returncode,
        stdout=proc.stdout[:MAX_CAPTURE_BYTES],
        stderr=proc.stderr[:MAX_CAPTURE_BYTES],
    )


class CapeHostOps:
    """
    Fixed operations against the CAPE container and its analysis VMs.

    `ctx` is the controller ledger. It is required, not optional: every
    task-scoped and VM-scoped call authorises against it, and making it a
    constructor argument means a call site cannot skip the check by leaving
    an argument out.
    """

    def __init__(
        self,
        ctx: RunContext,
        container: str = "cape",
        docker_bin: Optional[str] = None,
        default_timeout: int = 30,
    ):
        self.ctx = ctx
        self.container = container
        self.docker = docker_bin or shutil.which("docker") or "docker"
        self.default_timeout = default_timeout

    # ── plumbing ──────────────────────────────────────────────────────────

    def _exec(self, argv: Sequence[str], timeout: Optional[int] = None) -> CommandResult:
        """Run argv inside the CAPE container. No shell, no `bash -c`."""
        return _run(
            [self.docker, "exec", self.container, *argv],
            timeout=timeout if timeout is not None else self.default_timeout,
        )

    def _check_vm(self, vm_name: str, *, mutating: bool) -> str:
        if vm_name not in ALLOWED_VMS:
            raise HostOpError(
                f"{vm_name!r} is not a known analysis VM; allowed: {sorted(ALLOWED_VMS)}"
            )
        if mutating:
            # Raises LedgerRejected when this run does not hold the lease.
            self.ctx.require_vm_lease(vm_name)
        return vm_name

    def _check_task(self, task_id: int) -> int:
        receipt = self.ctx.require_task(task_id)
        return receipt.task_id

    # ── CAPE services ─────────────────────────────────────────────────────

    def services_active(self) -> tuple[bool, str]:
        """
        Whether CAPE's services report active.

        The old string was `systemctl is-active ... 2>/dev/null` inside
        `bash -c`, with the result matched for the substrings "inactive" and
        "failed". `is-active` already communicates through its exit code, so
        the code is what is read here; the text is returned for the log.
        """
        r = self._exec(["systemctl", "is-active", *CAPE_SERVICES])
        return r.ok, r.combined

    def restart_services(self, timeout: int = 120) -> CommandResult:
        return self._exec(["systemctl", "restart", *CAPE_SERVICES], timeout=timeout)

    # ── VM lifecycle ──────────────────────────────────────────────────────

    def vm_state(self, vm_name: str) -> str:
        """`virsh domstate`, or "unknown" when the call itself failed."""
        self._check_vm(vm_name, mutating=False)
        r = self._exec(["virsh", "domstate", vm_name])
        return r.stdout.strip() if r.ok else "unknown"

    def vm_start(self, vm_name: str, timeout: int = 60) -> CommandResult:
        self._check_vm(vm_name, mutating=True)
        return self._exec(["virsh", "start", vm_name], timeout=timeout)

    def vm_destroy(self, vm_name: str, timeout: int = 60) -> CommandResult:
        """
        Force the VM off.

        The old form ended in `|| true`, which discarded the distinction
        between "was already off" and "libvirt refused". The caller now gets
        the result and decides; `_fix_agent_unreachable` treats an already-off
        VM as fine and a refusal as a failed recovery.
        """
        self._check_vm(vm_name, mutating=True)
        return self._exec(["virsh", "destroy", vm_name], timeout=timeout)

    def vm_snapshot_revert(
        self, vm_name: str, snapshot: str, timeout: int = 120
    ) -> CommandResult:
        self._check_vm(vm_name, mutating=True)
        if snapshot not in ALLOWED_SNAPSHOTS:
            raise HostOpError(
                f"{snapshot!r} is not a known snapshot; allowed: {sorted(ALLOWED_SNAPSHOTS)}"
            )
        return self._exec(
            ["virsh", "snapshot-revert", vm_name, snapshot], timeout=timeout
        )

    # ── guest agent ───────────────────────────────────────────────────────

    def agent_reachable(self, ip: str, port: int, wait_s: int = 3) -> bool:
        """
        TCP reachability of the in-guest agent.

        `nc -zw3 IP PORT && echo UP || echo DOWN` became an exit-code check.
        `ip` and `port` are validated because they are formatted into argv,
        and while argv is not shell, a caller passing something unexpected
        should fail here rather than produce a confusing nc error.
        """
        import ipaddress

        ipaddress.ip_address(ip)          # raises ValueError on anything else
        port = int(port)
        if not (0 < port < 65536):
            raise HostOpError(f"port out of range: {port}")
        r = self._exec(
            ["nc", "-z", "-w", str(int(wait_s)), ip, str(port)],
            timeout=wait_s + 5,
        )
        return r.ok

    # ── analysis artefacts ────────────────────────────────────────────────

    def report_exists(self, task_id: int, storage_root: str) -> bool:
        """
        Whether CAPE has written a report for a task this run owns.

        This is the call the audit traces from `update_spec` to `shell=True`:
        the old form interpolated the model-writable task ID into
        `bash -c 'test -f /opt/CAPEv2/storage/analyses/{task_id}/reports/report.json ...'`.
        Now the ID is an int the controller recorded, the path is assembled in
        Python, and `test` runs as argv with no shell to reinterpret it.
        """
        task_id = self._check_task(task_id)
        path = f"{storage_root.rstrip('/')}/{task_id}/reports/report.json"
        return self._exec(["test", "-f", path]).ok
