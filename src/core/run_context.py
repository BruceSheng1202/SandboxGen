#!/usr/bin/env python3
"""
core/run_context.py — controller-only run ledger

SG-CTL-02 remediation, part 1 of 5.

The old design used a single `EnvironmentSpec` dict as both the agents'
scratchpad and the authorization root. Any agent could `update_spec` any
dotted path with any value, and the harness then read authorization-bearing
fields (`sample.path`, `cape_submission.pass2_task_id`, `network.mode`, …)
straight back out of that same mutable document. "Pinned facts" only ever
asserted authority in prompt text; it carried no enforcement.

`RunContext` is the replacement root of trust. It holds the facts that decide
what the harness is *allowed to do*, and no agent-reachable code path can
write to it:

  * the sample's identity, resolved once by the controller before any agent
    starts, and pinned by (device, inode) rather than by a path string;
  * real CAPE task IDs, admitted only from submit receipts and only as
    positive integers;
  * the network route policy actually submitted to CAPE;
  * the VM lease held by this run;
  * digests of reports the controller itself has verified.

Every mutation goes through a typed method, is validated at the boundary, and
is appended to an in-memory journal so the sequence can be replayed when a run
is audited. Agents receive `AgentFacts` — a read-only projection — and never a
reference to this object.

Threading: a run is single-threaded through the orchestrator, but the ledger
is cheap to guard, so mutators take a re-entrant lock rather than documenting
a constraint nobody will check.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


# ── Errors ────────────────────────────────────────────────────────────────────


class LedgerError(Exception):
    """Base class for every controller-ledger rejection."""


class LedgerSealed(LedgerError):
    """A write was attempted against a field that is already fixed."""


class LedgerRejected(LedgerError):
    """A write was rejected because the value failed validation."""


# ── Safe file opening ─────────────────────────────────────────────────────────
#
# SG-DATA-01 lists FIFOs and device nodes as a way to block a worker forever:
# `open()` on a FIFO with no writer blocks in the kernel, and no application
# timeout helps because the process never reaches user code again. O_NONBLOCK
# makes that open return immediately so the file type can be checked, and
# O_NOFOLLOW keeps a symlink swapped in at the last moment from redirecting it.
# Both are cleared once the descriptor is confirmed to be a regular file.
_SAFE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _clear_nonblock(fd: int) -> None:
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)


# ── Value objects ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SampleIdentity:
    """
    The sample as the controller resolved it, before any agent ran.

    SG-DATA-02: authorization must not be derivable from a mutable path
    string. Device and inode identify the file object observed at binding;
    `matches()` and `open_sample()` compare those values on later access.
    They do not revalidate content or detect reuse of a deleted inode.
    Keep the sample and its containing directory protected from modification
    throughout the run. The recorded digest describes the initial read.
    """

    path: Path
    sha256: str
    size_bytes: int
    device: int
    inode: int

    def matches(self, candidate: Path) -> bool:
        """Compare device and inode; this does not verify the current content."""
        try:
            st = candidate.stat()
        except OSError:
            return False
        return st.st_dev == self.device and st.st_ino == self.inode

    def as_facts(self) -> dict:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class TaskReceipt:
    """
    A CAPE task the controller itself submitted.

    SG-CTL-01: `task_id` is an int here and nowhere becomes a string that an
    agent chose. Anything that builds a command uses `TaskReceipt.task_id`,
    so the value reaching argv is an integer by construction rather than by
    a validation step somebody can forget to call.
    """

    task_id: int
    pass_number: int
    sample_sha256: str
    submitted_at: float
    route: str
    machine: Optional[str] = None

    def as_facts(self) -> dict:
        return {
            "task_id": self.task_id,
            "pass_number": self.pass_number,
            "route": self.route,
            "machine": self.machine,
        }


@dataclass(frozen=True)
class ReportDigest:
    """A report the controller fetched and hashed itself."""

    task_id: int
    sha256: str
    path: Path
    target_sha256_matches: bool
    fetched_at: float


@dataclass(frozen=True)
class VMLease:
    """
    The analysis VM this run holds.

    SG-CONC-01: Base, Retry and manual maintenance scripts could all drive the
    same fixed VM names with no lease, so one run could destroy another's
    machine mid-analysis. The lease does not by itself make VM control safe —
    that needs the broker in P0-3 — but it gives the harness a value to check
    before it issues a destructive operation, and a name to put in the error
    when it refuses.
    """

    vm_name: str
    lease_id: str
    acquired_at: float
    expires_at: float

    def is_valid(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at


@dataclass(frozen=True)
class AgentFacts:
    """
    The read-only projection agents are given.

    This is what replaces "pinned facts" in the system prompt. The difference
    that matters is not that the text says the values are authoritative — the
    old prompt said that too — but that the harness now reads authorization
    from `RunContext` and never from anything an agent can write, so an agent
    contradicting these facts changes nothing but its own transcript.
    """

    run_id: str
    sample: dict
    tasks: list
    route_policy: str
    vm_name: Optional[str]
    verified_report: Optional[dict]

    def to_prompt_block(self) -> str:
        lines = [
            f"  run_id: {self.run_id}",
            f"  sample.sha256: {self.sample.get('sha256')}",
            f"  sample.size_bytes: {self.sample.get('size_bytes')}",
            f"  network.route: {self.route_policy}",
        ]
        if self.vm_name:
            lines.append(f"  analysis_vm: {self.vm_name}")
        for t in self.tasks:
            lines.append(f"  cape_task[pass{t['pass_number']}]: {t['task_id']} "
                         f"(route {t['route']}, "
                         f"{'confirmed by CAPE' if t.get('route_verified') else 'route UNCONFIRMED'})")
        if self.verified_report:
            lines.append(
                f"  verified_report[task {self.verified_report['task_id']}]: "
                f"sha256={self.verified_report['sha256']}"
            )
        return "\n".join(lines)


# ── The ledger ────────────────────────────────────────────────────────────────

_VALID_ROUTES = frozenset({"drop", "none", "internet", "inetsim", "tor", "vpn"})

# A run may not create unbounded CAPE work. SG-DATA-03 / SG-BUDGET-01: without
# a cap, one prompt-injected response containing many submits — or a retry loop
# reacting to 503s — floods the queue and starves every other experiment.
MAX_TASKS_PER_RUN = 8

# CAPE task IDs come from a Django AutoField, i.e. a 32-bit signed sequence.
# Python ints are arbitrary precision, so "positive int" alone still admits
# values with thousands of digits — which then get formatted into argv, log
# lines and JSON. SG-CTL-01's acceptance criteria call for an oversized-integer
# property test; this is the bound it asserts against.
MAX_TASK_ID = 2**31 - 1


class RunContext:
    """
    Controller-only state for one pipeline run.

    Nothing on this object is reachable from an agent tool. `AgentLoop` is
    handed `facts()`, never `self`.
    """

    def __init__(self, run_id: str, workspace: Path):
        self.run_id = run_id
        self.workspace = workspace
        self._lock = threading.RLock()

        self._sample: Optional[SampleIdentity] = None
        self._tasks: list[TaskReceipt] = []
        self._reports: dict[int, ReportDigest] = {}
        self._route_confirmations: dict[int, dict] = {}
        self._route_policy: str = "drop"          # fail closed until set
        # Offline by default: agents get no internet tools. The orchestrator
        # sets this True only for a --url/--repo run, whose task is to fetch
        # the sample (SG-eval integrity / containment).
        self.allow_sample_download: bool = False
        self._vm_lease: Optional[VMLease] = None
        self._journal: list[dict] = []

        self._record("run_started", {"run_id": run_id, "workspace": str(workspace)})

    # ── journal ───────────────────────────────────────────────────────────

    def _record(self, event: str, payload: dict) -> None:
        self._journal.append(
            {"at": time.time(), "event": event, **payload}
        )

    def journal(self) -> list[dict]:
        """A copy of the mutation history, for the run manifest."""
        return list(self._journal)

    # ── sample ────────────────────────────────────────────────────────────

    def bind_sample(self, path: Path) -> SampleIdentity:
        """
        Resolve, validate and pin the sample. Callable exactly once, by the
        orchestrator, before any agent starts.

        The initial stat and digest use the same open descriptor. This does
        not freeze the file: concurrent writes, later content changes, and
        inode reuse are not prevented. Callers must protect the input from
        modification; a later `matches()` check only compares device/inode.
        """
        with self._lock:
            if self._sample is not None:
                raise LedgerSealed(
                    f"sample already bound to sha256={self._sample.sha256}; "
                    "a run analyses exactly one sample"
                )

            resolved = Path(path).resolve(strict=True)
            fd = os.open(resolved, _SAFE_OPEN_FLAGS)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise LedgerRejected(
                        f"sample must be a regular file, got mode {stat.filemode(st.st_mode)}: "
                        f"{resolved}"
                    )
                # Safe to clear now that the descriptor is known to be a regular
                # file: O_NONBLOCK was only ever there to survive the open.
                _clear_nonblock(fd)
                digest = hashlib.sha256()
                read_total = 0
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    read_total += len(chunk)
            finally:
                os.close(fd)

            identity = SampleIdentity(
                path=resolved,
                sha256=digest.hexdigest(),
                size_bytes=read_total,
                device=st.st_dev,
                inode=st.st_ino,
            )
            self._sample = identity
            self._record(
                "sample_bound",
                {"sha256": identity.sha256, "size_bytes": identity.size_bytes,
                 "path": str(resolved)},
            )
            return identity

    @property
    def sample(self) -> SampleIdentity:
        if self._sample is None:
            raise LedgerError("sample has not been bound yet")
        return self._sample

    @property
    def has_sample(self) -> bool:
        """Whether `bind_sample` has run. Lets a caller branch without catching."""
        return self._sample is not None

    @property
    def vm_lease(self) -> Optional[VMLease]:
        return self._vm_lease

    def open_sample(self):
        """
        Open the sample and reject a non-regular file or changed device/inode.
        Callers receive a file object. Content changes within the same inode
        and reuse of a deleted inode are not detected by this check.
        """
        identity = self.sample
        fd = os.open(identity.path, _SAFE_OPEN_FLAGS)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise LedgerRejected(
                    f"{identity.path} is no longer a regular file "
                    f"(mode {stat.filemode(st.st_mode)})"
                )
            if st.st_dev != identity.device or st.st_ino != identity.inode:
                raise LedgerRejected(
                    f"{identity.path} no longer resolves to the bound sample "
                    f"(dev/inode changed since it was pinned)"
                )
            _clear_nonblock(fd)
        except Exception:
            os.close(fd)
            raise
        return os.fdopen(fd, "rb")

    # ── route policy ──────────────────────────────────────────────────────

    def set_route_policy(self, route: str) -> None:
        """
        Record the route the controller will actually submit to CAPE.

        SG-NET-01: the old code decided a network mode and then never checked
        that the value reached CAPE's `route` field. Storing it here gives the
        submit path one value to send and the verification path one value to
        compare the accepted task against.
        """
        with self._lock:
            if route not in _VALID_ROUTES:
                raise LedgerRejected(
                    f"unknown route {route!r}; expected one of {sorted(_VALID_ROUTES)}"
                )
            self._route_policy = route
            self._record("route_policy_set", {"route": route})

    @property
    def route_policy(self) -> str:
        return self._route_policy

    # ── tasks ─────────────────────────────────────────────────────────────

    def record_task(
        self,
        task_id: Any,
        pass_number: int,
        route: str,
        machine: Optional[str] = None,
    ) -> TaskReceipt:
        """
        Admit a CAPE task ID from a submit receipt.

        SG-CTL-01: this is the only door through which a task ID enters the
        run, and it closes on anything that is not a positive integer. `bool`
        is rejected explicitly because it is an `int` subclass and `True`
        would otherwise become task 1.
        """
        with self._lock:
            if isinstance(task_id, bool) or not isinstance(task_id, int):
                raise LedgerRejected(
                    f"task_id must be an int, got {type(task_id).__name__}: {task_id!r}"
                )
            if not (0 < task_id <= MAX_TASK_ID):
                raise LedgerRejected(
                    f"task_id must be within (0, {MAX_TASK_ID}], got {task_id}"
                )
            if len(self._tasks) >= MAX_TASKS_PER_RUN:
                raise LedgerRejected(
                    f"run already holds {len(self._tasks)} CAPE tasks "
                    f"(limit {MAX_TASKS_PER_RUN})"
                )
            if any(t.task_id == task_id for t in self._tasks):
                raise LedgerRejected(f"task {task_id} is already recorded for this run")
            if route not in _VALID_ROUTES:
                raise LedgerRejected(f"unknown route {route!r} for task {task_id}")

            receipt = TaskReceipt(
                task_id=task_id,
                pass_number=int(pass_number),
                sample_sha256=self.sample.sha256,
                submitted_at=time.time(),
                route=route,
                machine=machine,
            )
            self._tasks.append(receipt)
            self._record(
                "task_recorded",
                {"task_id": task_id, "pass": receipt.pass_number, "route": route},
            )
            return receipt

    def confirm_task_route(self, task_id: int, effective_route: Optional[str]) -> bool:
        """
        Record what CAPE says the task's route is, and whether it equals the
        route this run asked for.

        SG-NET-01: the old code decided a mode and never learned whether it
        reached CAPE. A task whose route cannot be read back, or comes back
        different (an `inetsim` request on a server without inetsim is stored
        as something else), is recorded as unverified; `route_verified()`
        stays False for it and the run cannot count it as a success.
        """
        with self._lock:
            receipt = self.require_task(task_id)
            ok = effective_route is not None and effective_route == receipt.route
            self._route_confirmations[receipt.task_id] = {
                "requested": receipt.route,
                "effective": effective_route,
                "verified": ok,
            }
            self._record("task_route_checked",
                         {"task_id": receipt.task_id, "requested": receipt.route,
                          "effective": effective_route, "verified": ok})
            return ok

    def route_verified(self, task_id: Any) -> bool:
        """True only when CAPE confirmed the route this run requested."""
        entry = self._route_confirmations.get(task_id)
        return bool(entry and entry["verified"])

    def owns_task(self, task_id: Any) -> bool:
        """Whether this run submitted `task_id`. Used before any task-scoped call."""
        if isinstance(task_id, bool) or not isinstance(task_id, int):
            return False
        return any(t.task_id == task_id for t in self._tasks)

    def require_task(self, task_id: Any) -> TaskReceipt:
        """
        Fetch a receipt, refusing IDs this run did not create.

        SG-AUTH-01: CAPE task IDs are sequential and the client holds a
        superuser token, so an agent that guesses a neighbouring ID could
        otherwise read another project's analysis. Ownership is checked
        against the ledger, not against what the model claims.
        """
        for t in self._tasks:
            if t.task_id == task_id:
                return t
        raise LedgerRejected(
            f"task {task_id!r} was not submitted by run {self.run_id}; refusing"
        )

    @property
    def tasks(self) -> list[TaskReceipt]:
        return list(self._tasks)

    def latest_task(self) -> Optional[TaskReceipt]:
        return self._tasks[-1] if self._tasks else None

    # ── reports ───────────────────────────────────────────────────────────

    def record_report(
        self, task_id: int, report_path: Path, target_sha256_matches: bool
    ) -> ReportDigest:
        """
        Hash a report the controller fetched, and bind it to a task this run owns.

        SG-INT-02: a report hash proves the file has not changed since it was
        read; it does not prove the analysis ran this sample. That is why the
        target-hash comparison is stored beside the digest instead of being
        folded into one "verified" boolean — the caller has to decide what an
        unverified report may be used for, and `verified_report()` will not
        hand one out.
        """
        with self._lock:
            receipt = self.require_task(task_id)
            data = Path(report_path).read_bytes()
            digest = ReportDigest(
                task_id=receipt.task_id,
                sha256=hashlib.sha256(data).hexdigest(),
                path=Path(report_path),
                target_sha256_matches=target_sha256_matches,
                fetched_at=time.time(),
            )
            self._reports[receipt.task_id] = digest
            self._record(
                "report_recorded",
                {
                    "task_id": receipt.task_id,
                    "sha256": digest.sha256,
                    "target_sha256_matches": target_sha256_matches,
                },
            )
            return digest

    def verified_report(self) -> Optional[ReportDigest]:
        """
        The newest report whose analysis target matched the bound sample.

        A report that failed the target check is deliberately not returned:
        SG-INT-02 and round-1 INT-04 both describe the old behaviour of
        recording `verified=False` and then using the report anyway.
        """
        candidates = [d for d in self._reports.values() if d.target_sha256_matches]
        if not candidates:
            return None
        return max(candidates, key=lambda d: d.fetched_at)

    # ── VM lease ──────────────────────────────────────────────────────────

    def acquire_vm_lease(self, vm_name: str, ttl_seconds: float) -> VMLease:
        with self._lock:
            if self._vm_lease is not None and self._vm_lease.is_valid():
                raise LedgerSealed(
                    f"run already holds a lease on {self._vm_lease.vm_name}"
                )
            lease = VMLease(
                vm_name=vm_name,
                lease_id=f"{self.run_id}:{int(time.time())}",
                acquired_at=time.time(),
                expires_at=time.time() + float(ttl_seconds),
            )
            self._vm_lease = lease
            self._record("vm_lease_acquired", {"vm": vm_name, "lease": lease.lease_id})
            return lease

    def require_vm_lease(self, vm_name: str) -> VMLease:
        """Refuse a VM operation unless this run holds a live lease on that VM."""
        lease = self._vm_lease
        if lease is None:
            raise LedgerRejected(f"run {self.run_id} holds no VM lease; refusing {vm_name}")
        if lease.vm_name != vm_name:
            raise LedgerRejected(
                f"run {self.run_id} holds a lease on {lease.vm_name}, not {vm_name}"
            )
        if not lease.is_valid():
            raise LedgerRejected(
                f"lease {lease.lease_id} on {vm_name} expired at {lease.expires_at}"
            )
        return lease

    def release_vm_lease(self) -> None:
        with self._lock:
            if self._vm_lease is not None:
                self._record("vm_lease_released", {"vm": self._vm_lease.vm_name})
                self._vm_lease = None

    # ── projection ────────────────────────────────────────────────────────

    def facts(self) -> AgentFacts:
        """The read-only view handed to agents."""
        verified = self.verified_report()
        return AgentFacts(
            run_id=self.run_id,
            sample=self._sample.as_facts() if self._sample else {},
            tasks=[{**t.as_facts(), "route_verified": self.route_verified(t.task_id)}
                   for t in self._tasks],
            route_policy=self._route_policy,
            vm_name=self._vm_lease.vm_name if self._vm_lease else None,
            verified_report=(
                {"task_id": verified.task_id, "sha256": verified.sha256}
                if verified
                else None
            ),
        )

    # ── manifest ──────────────────────────────────────────────────────────

    def manifest(self) -> dict:
        """
        The controller's account of the run.

        SG-INT-01 / round-1 INT-07: batch tooling must decide completion from
        a manifest the controller signed off on, not from a directory being
        non-empty. This produces the content; writing and signing it belongs
        to the orchestrator.
        """
        verified = self.verified_report()
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "workspace": str(self.workspace),
            "sample": self._sample.as_facts() if self._sample else None,
            "route_policy": self._route_policy,
            "tasks": [asdict(t) for t in self._tasks],
            "route_confirmations": dict(self._route_confirmations),
            "verified_report": (
                {
                    "task_id": verified.task_id,
                    "sha256": verified.sha256,
                    "path": str(verified.path),
                }
                if verified
                else None
            ),
            "journal": self._journal,
        }

    def write_manifest(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp{os.getpid()}")
        with open(tmp, "w") as f:
            json.dump(self.manifest(), f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        return path
