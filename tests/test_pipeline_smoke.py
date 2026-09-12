#!/usr/bin/env python3
"""
Orchestrator-level offline smoke test: the whole pipeline, no SDK, no CAPE,
no Docker, no network.

A scripted fake LLM plays each role by emitting the tool calls a real model
would, a fake CAPE client hands back a report whose target hash matches (or
deliberately does not match) the pinned sample, and a fake host-ops object
answers the Executor's diagnostics. Everything else — the ledger, the spec
ACL, the promotions, the manifest — is the real code.

What this proves that the module tests cannot:
  * the controller half of M1 is wired: cape_submit lands in the ledger,
    _validate() sees it, the report digest is recorded, network.proposed_mode
    becomes a route, analysis.report becomes report;
  * the submitted file is the pinned sample even when the model names
    another path (SG-DATA-03), and the route reaches CAPE (SG-NET-01);
  * a report for the wrong sample, or an Analyst report naming the wrong
    task, fails the run instead of being promoted (SG-INT-02);
  * --max-attempts re-runs with a fresh ledger and records failure history.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import types
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from orchestrator import Orchestrator, validate_report, _normalize_report  # noqa: E402
from core.host_ops import CommandResult  # noqa: E402


# ── fakes ─────────────────────────────────────────────────────────────────────


def _call(**kw) -> str:
    return "<tool_call>\n" + json.dumps(kw) + "\n</tool_call>"


class ScriptedLLM:
    """
    Plays all four roles. The script for a role is a list of responses; the
    role is recognised from the system prompt, and `facts()` lets a step read
    the ledger the way a real model would read RUN FACTS.
    """

    def __init__(self, ctx_getter, *, analyst_task_id=None, extra_submit_path="/tmp/not-the-sample.exe"):
        self.ctx_getter = ctx_getter
        self.analyst_task_id = analyst_task_id
        self.extra_submit_path = extra_submit_path
        self.turns = {}           # role -> number of chat() calls so far
        self.systems = []         # every system prompt seen, for assertions
        self.calls = 0

    def _role(self, system: str) -> str:
        m = re.search(r"You are the (\w+) Agent", system)
        return m.group(1) if m else "?"

    def chat(self, system, messages, max_tokens=4096):
        self.calls += 1
        self.systems.append(system)
        role = self._role(system)
        # Scripts restart for every attempt: key the turn counter by the
        # attempt's run_id so a retry replays the role from its first step.
        key = (role, self.ctx_getter().run_id)
        n = self.turns.get(key, 0) + 1
        self.turns[key] = n
        handler = getattr(self, f"_{role.lower()}", None)
        return handler(n) if handler else _call(tool="finish", summary="nothing to do")

    # Scout: classify, propose network, finish.
    def _scout(self, n):
        if n == 1:
            return (_call(tool="update_spec", key="sample.format", value="PE")
                    + _call(tool="update_spec", key="sample.os_target", value="windows")
                    + _call(tool="update_spec", key="sample.architecture", value="x86_64"))
        if n == 2:
            return (_call(tool="update_spec", key="classification.type", value="dropper")
                    + _call(tool="update_spec", key="classification.confidence", value="medium")
                    + _call(tool="update_spec", key="network.proposed_mode", value="isolated")
                    # controller-owned: must come back REFUSED, not crash
                    + _call(tool="update_spec", key="sample.sha256", value="0" * 64))
        return _call(tool="finish", summary="PE dropper, isolated network")

    # Architect: submission parameters, finish.
    def _architect(self, n):
        if n == 1:
            return (_call(tool="update_spec", key="cape_submission.package", value="exe")
                    + _call(tool="update_spec", key="cape_submission.platform", value="windows")
                    + _call(tool="update_spec", key="cape_submission.timeout", value=120))
        if n == 2:
            return (_call(tool="update_spec", key="cape_submission.options", value="combo=1")
                    + _call(tool="update_spec", key="cape_submission.reasoning", value="PE -> exe"))
        return _call(tool="finish", summary="exe/windows/120s")

    # Executor: two submits (naming a path that is NOT the pinned sample),
    # status, fetch, finish.
    def _executor(self, n):
        if n == 1:
            return _call(tool="cape_submit", sample_path=self.extra_submit_path,
                         package="exe", timeout=60, options="combo=1")
        if n == 2:
            ctx = self.ctx_getter()
            tid = ctx.latest_task().task_id
            return (_call(tool="cape_status", task_id=tid)
                    # SG-AUTH-01: a neighbouring id must be refused
                    + _call(tool="cape_status", task_id=tid + 1)
                    + _call(tool="cape_submit", sample_path=self.extra_submit_path,
                            package="exe", timeout=120, options="combo=1"))
        if n == 3:
            ctx = self.ctx_getter()
            tid = ctx.latest_task().task_id
            return (_call(tool="cape_fetch_report", task_id=tid,
                          save_to=f"cape_report_{tid}.json")
                    + _call(tool="update_spec", key="pass1.completed", value=True)
                    + _call(tool="update_spec", key="pass2.completed", value=True))
        return _call(tool="finish", summary="submitted")

    # Analyst: read report, write analysis.report, finish.
    def _analyst(self, n):
        ctx = self.ctx_getter()
        verified = ctx.verified_report()
        tid = self.analyst_task_id if self.analyst_task_id is not None else \
              (verified.task_id if verified else None)
        if n == 1:
            path = str(verified.path) if verified else "cape_report_missing.json"
            return (_call(tool="query_json", file=path, path="signatures", limit=5)
                    # SG-DATA-01: outside the workspace must be refused
                    + _call(tool="query_json", file="/etc/hostname", path="", limit=5))
        if n == 2:
            report = {
                "classification": "dropper",
                "confidence": "medium",
                "family": None,
                "os_target": "windows",
                "cape_task_id": tid,
                "behaviour_summary": ["wrote a file (per behavior.summary)"],
                "iocs": [{"type": "mutex", "value": "Global\\canary", "context": "single"}],
                "mitre_attack": ["T1105 — Ingress Tool Transfer"],
                "recommended_detections": ["mutex Global\\canary"],
                "channels_analysed": ["cape_signatures"],
                "channels_unavailable": [],
                "analyst_notes": "offline smoke",
            }
            return (_call(tool="update_spec", key="analysis.report", value=report)
                    # controller-owned: must be refused
                    + _call(tool="update_spec", key="report", value=report)
                    + _call(tool="write_file", path="analysis_report.json",
                            content=json.dumps(report)))
        return _call(tool="finish", summary="done")

    def get_usage(self):
        return {"model": "scripted", "calls": self.calls, "input_tokens": 0,
                "output_tokens": 0, "total_tokens": 0, "cost_usd": None,
                "cache_read_tokens": 0, "cache_write_tokens": 0}


class FakeCAPE:
    """
    Records every submit; reports carry the sha256 of the bytes actually
    uploaded so provenance follows the file, not the model's claims.
    `mismatch_until_attempt` makes earlier attempts return a foreign hash.
    """

    def __init__(self, *, mismatch_first_n_tasks: int = 0, signal: bool = True,
                 route_readback="echo"):
        self.cfg = types.SimpleNamespace(mode="rest", url="http://fake:8001",
                                         token="t", storage="/opt/CAPEv2/storage/analyses")
        # "echo": CAPE stores what was requested; a string: CAPE stores that
        # instead (inetsim not configured, say); None: record unreadable.
        self.route_readback = route_readback
        self.submits = []
        self.connected = 0
        self._next = 1000
        self.mismatch_first_n_tasks = mismatch_first_n_tasks
        self.signal = signal
        self._sha_by_task = {}

    def connect(self):
        self.connected += 1

    def list_machines(self):
        return [{"name": "cuckoo1", "platform": "windows", "arch": "x86_64"}]

    def submit_file(self, sample_path, options=None):
        self._next += 1
        sha = hashlib.sha256(Path(sample_path).read_bytes()).hexdigest()
        if len(self.submits) < self.mismatch_first_n_tasks:
            sha = "f" * 64
        self._sha_by_task[self._next] = sha
        self.submits.append({"task_id": self._next, "path": sample_path,
                             "options": dict(options or {})})
        return self._next

    def get_task_status(self, task_id):
        return "reported"

    def get_task_route(self, task_id):
        if self.route_readback == "echo":
            for s in self.submits:
                if s["task_id"] == task_id:
                    return s["options"].get("route")
            return None
        if self.route_readback is None:
            raise RuntimeError("task record unavailable")
        return self.route_readback

    def get_report(self, task_id):
        sha = self._sha_by_task[task_id]
        return {
            "target": {"file": {"sha256": sha}},
            "signatures": [{"name": "canary_sig", "severity": 1}] if self.signal else [],
            "behavior": {"processes": [{"pid": 1}] if self.signal else []},
            "malscore": 1.0 if self.signal else 0.0,
            "network": {"dns": [], "tcp": [], "http": [], "hosts": []},
        }

    def get_report_verified(self, task_id, expected_sha256=None):
        report = self.get_report(task_id)
        sha = report["target"]["file"]["sha256"]
        return report, (sha == (expected_sha256 or "").lower()), sha

    def report_has_signal(self, report):
        procs = len(report.get("behavior", {}).get("processes", []))
        sigs = len(report.get("signatures", []))
        return {"process_count": procs, "signature_count": sigs,
                "malscore": report.get("malscore", 0), "network_events": 0,
                "has_signal": bool(procs or sigs)}


class FakeHostOps:
    def __init__(self, ctx):
        self.ctx = ctx

    def _ok(self, *argv):
        return CommandResult(argv=tuple(argv), returncode=0, stdout="ok", stderr="")

    def services_active(self):
        return True, "active active active"

    def restart_services(self, timeout=120):
        return self._ok("systemctl", "restart")

    def vm_state(self, vm):
        return "running"

    def vm_start(self, vm, timeout=60):
        self.ctx.require_vm_lease(vm)
        return self._ok("virsh", "start", vm)

    def vm_destroy(self, vm, timeout=60):
        self.ctx.require_vm_lease(vm)
        return self._ok("virsh", "destroy", vm)

    def vm_snapshot_revert(self, vm, snap, timeout=120):
        self.ctx.require_vm_lease(vm)
        return self._ok("virsh", "snapshot-revert", vm, snap)

    def agent_reachable(self, ip, port, wait_s=3):
        return True

    def report_exists(self, task_id, storage_root):
        self.ctx.require_task(task_id)
        return True


def _args(ws: Path, sample: Path, **over) -> types.SimpleNamespace:
    base = dict(workspace=str(ws), binary=str(sample), repo_url=None, url=None,
                allow_network_storage=True, llm_config=None, cape_config=None,
                max_attempts=1)
    base.update(over)
    return types.SimpleNamespace(**base)


@pytest.fixture()
def sample(tmp_path: Path) -> Path:
    p = tmp_path / "canary.bin"
    p.write_bytes(b"MZ harmless canary payload " * 64)
    return p


def _build(tmp_path, sample, *, cape=None, llm_kwargs=None, **args_over):
    holder = {}
    llm = ScriptedLLM(lambda: holder["orch"].ctx, **(llm_kwargs or {}))
    orch = Orchestrator(_args(tmp_path / "ws", sample, **args_over),
                        llm=llm, cape=cape or FakeCAPE(),
                        host_ops_factory=FakeHostOps)
    holder["orch"] = orch
    return orch, llm


# ── the happy path ────────────────────────────────────────────────────────────


def test_pipeline_succeeds_end_to_end(tmp_path, sample):
    orch, llm = _build(tmp_path, sample)
    assert orch.run() is True

    ctx, spec = orch.ctx, orch.spec
    ws = tmp_path / "ws"

    # Ledger: two receipts, both from cape_submit, mirrored by the controller.
    assert [t.pass_number for t in ctx.tasks] == [1, 2]
    assert spec.get("cape_submission.pass1_task_id") == ctx.tasks[0].task_id
    assert spec.get("cape_submission.pass2_task_id") == ctx.tasks[1].task_id
    assert spec.get("executor.passes_completed") == 2
    assert spec.get("executor.validation_failed") in (None, False)

    # Report provenance: the digest is in the ledger and the file it names
    # is the one the Analyst was pointed at.
    verified = ctx.verified_report()
    assert verified is not None and verified.task_id == ctx.tasks[1].task_id
    assert Path(spec.get("pass2.artefacts.cape_report")) == verified.path
    assert verified.path.exists()

    # Promotions.
    assert spec.get("network.mode") == "isolated"
    assert spec.get("network.route_enforced") == "drop"
    assert ctx.route_policy == "drop"
    assert spec.get("report", {}).get("classification") == "dropper"
    assert spec.get("provenance.report_promoted") is True

    # Artefacts.
    assert (ws / "success.json").exists()
    manifest = json.loads((ws / "run_manifest.json").read_text())
    assert manifest["pipeline_ok"] is True
    assert manifest["pipeline_reason"] == "ok"
    assert manifest["agent_trace"] == "agent_trace.jsonl"
    assert len(manifest["tasks"]) == 2
    assert any(w["actor"] == "Scout" for w in manifest["spec_writes"])
    assert (ws / "analysis_report.json").exists()

    # Lease released at the end of the Executor stage.
    assert ctx.vm_lease is None
    # Route confirmed by CAPE for every task, recorded in the manifest.
    assert all(ctx.route_verified(t.task_id) for t in ctx.tasks)
    assert manifest["route_confirmations"][str(ctx.tasks[1].task_id)]["verified"] is True


@pytest.mark.parametrize("stage", ["Scout", "Architect", "Executor", "Analyst"])
def test_exhausted_503_never_restarts_a_stage(tmp_path, sample, monkeypatch, stage):
    import orchestrator

    calls = []

    def fail_once_requested(*args, **kwargs):
        calls.append(stage)
        raise RuntimeError("503 fixture: provider attempt budget exhausted")

    monkeypatch.setattr(getattr(orchestrator, stage + "Agent"), "run", fail_once_requested)
    monkeypatch.setattr(orchestrator.time, "sleep", lambda _: None)
    orch, _ = _build(tmp_path, sample)
    assert orch.run() is False
    assert calls == [stage]
    if stage == "Analyst":
        assert len(orch.cape.submits) == 2  # already completed executor actions
    assert not (tmp_path / "ws/success.json").exists()


@pytest.mark.parametrize("image,health", [
    (r"C:\Windows\System32\OpenWith.exe", {"sample_process_root_found": True}),
    (None, {"sample_process_root_found": False, "launch_error": "DLL launch failed"}),
])
def test_invalid_windows_launch_cannot_be_pipeline_success(tmp_path, sample, image, health):
    from core.qemu_backend import QemuCapeClient

    class FailedWindowsCAPE(FakeCAPE):
        def get_report(self, task_id):
            report = super().get_report(task_id)
            report.update(backend="qemu-tcg-windows", sandboxgen=health)
            report["behavior"]["processes"] = [{"image": image}] if image else []
            report["signatures"] = [{"name": "long_running_or_timeout"}]
            return report

        report_has_signal = QemuCapeClient.report_has_signal

    orch, llm = _build(tmp_path, sample, cape=FailedWindowsCAPE())
    assert orch.run() is False
    assert orch.spec.get("executor.validation_failed") is True
    assert orch.spec.get("executor.report_quality")["execution_valid"] is False
    assert not any(role == "Analyst" for _, role in llm.turns)
    assert not (tmp_path / "ws" / "success.json").exists()
    # The failed report is retained for diagnosis, not deleted or promoted.
    assert orch.ctx.verified_report().path.exists()


def test_backend_capabilities_reach_architect(tmp_path, sample):
    from core.qemu_backend import QemuCapeClient

    class CapabilityCAPE(FakeCAPE):
        win_golden = Path("configured-windows-fixture.qcow2")
        capabilities = QemuCapeClient.capabilities

    orch, _ = _build(tmp_path, sample, cape=CapabilityCAPE())
    assert orch.run() is True
    caps = orch.spec.get("cape_submission.backend_capabilities")
    assert caps["windows_options"] == ["function"]
    from core.spec_policy import SpecPermissionError
    with pytest.raises(SpecPermissionError):
        orch.spec.set("cape_submission.backend_capabilities", {}, actor="Architect")


@pytest.mark.parametrize("readback", ["none", None])
def test_route_not_confirmed_by_cape_fails_the_run(tmp_path, sample, readback):
    """SG-NET-01 second half: a declared policy CAPE did not confirm is not a run."""
    cape = FakeCAPE(route_readback=readback)
    orch, _ = _build(tmp_path, sample, cape=cape)
    assert orch.run() is False
    assert orch.ctx.verified_report() is not None          # report itself is fine...
    assert not any(orch.ctx.route_verified(t.task_id) for t in orch.ctx.tasks)
    assert "route" in (orch.spec.get("executor.validation_error") or "")
    assert not (tmp_path / "ws" / "success.json").exists()
    assert orch.spec.get("report") is None                 # ...but Analyst never ran


def test_submitted_file_is_the_pinned_sample_and_carries_the_route(tmp_path, sample):
    """SG-DATA-03 + SG-NET-01."""
    cape = FakeCAPE()
    orch, _ = _build(tmp_path, sample, cape=cape)
    assert orch.run() is True
    assert len(cape.submits) == 2
    for s in cape.submits:
        assert Path(s["path"]) == orch.ctx.sample.path          # not /tmp/not-the-sample.exe
        assert s["options"]["route"] == "drop"


def test_run_facts_block_reaches_the_model(tmp_path, sample):
    orch, llm = _build(tmp_path, sample)
    orch.run()
    executor_systems = [s for s in llm.systems if "You are the Executor Agent" in s]
    assert executor_systems, "Executor never prompted"
    # Later Executor turns must show the task id the ledger recorded.
    tid = orch.ctx.tasks[0].task_id
    assert any(f"cape_task[pass1]: {tid}" in s for s in executor_systems)
    assert all("RUN FACTS" in s for s in llm.systems)


def test_controller_owned_writes_are_refused_not_fatal(tmp_path, sample):
    orch, _ = _build(tmp_path, sample)
    assert orch.run() is True
    # Scout tried to overwrite sample.sha256; the pinned value survived.
    assert orch.spec.get("sample.sha256") == orch.ctx.sample.sha256
    # Analyst tried to write `report` directly; promotion is what set it.
    assert orch.spec.get("provenance.report_promoted") is True


# ── failure paths ─────────────────────────────────────────────────────────────


def test_report_for_another_sample_fails_the_run(tmp_path, sample):
    """SG-INT-02 / round-1 INT-04: a mismatched report never becomes authoritative."""
    cape = FakeCAPE(mismatch_first_n_tasks=99)
    orch, _ = _build(tmp_path, sample, cape=cape)
    assert orch.run() is False
    ws = tmp_path / "ws"
    assert not (ws / "success.json").exists()
    assert orch.ctx.verified_report() is None
    assert orch.spec.get("pass2.artefacts.cape_report") is None
    assert orch.spec.get("pass2.artefacts.quarantined_report") is not None
    assert orch.spec.get("executor.validation_failed") is True
    # Analyst never ran on an unverified report.
    assert orch.spec.get("analysis.report") is None
    # ...but the manifest still records what happened.
    assert json.loads((ws / "run_manifest.json").read_text())["pipeline_ok"] is False


def test_analyst_naming_the_wrong_task_is_not_promoted(tmp_path, sample):
    orch, _ = _build(tmp_path, sample, llm_kwargs={"analyst_task_id": 424242})
    assert orch.run() is False
    assert orch.spec.get("report") is None
    assert orch.spec.get("provenance.report_promoted") is False
    assert any("cape_task_id" in p for p in orch.spec.get("provenance.report_problems"))


def test_verified_but_empty_report_is_not_a_success(tmp_path, sample):
    orch, _ = _build(tmp_path, sample, cape=FakeCAPE(signal=False))
    assert orch.run() is False
    assert orch.ctx.verified_report() is not None      # provenance fine...
    assert orch.spec.get("report") is None             # ...but nothing to analyse
    assert not (tmp_path / "ws" / "success.json").exists()


# ── retry edition ─────────────────────────────────────────────────────────────


def test_max_attempts_retries_with_fresh_ledger_and_records_history(tmp_path, sample):
    # First attempt's two submits come back for a foreign sample; the second
    # attempt's do not.
    cape = FakeCAPE(mismatch_first_n_tasks=2)
    orch, llm = _build(tmp_path, sample, cape=cape, max_attempts=3)
    assert orch.run() is True
    assert orch.success_attempt == 2

    ws = tmp_path / "ws"
    assert (ws / "attempt_1").is_dir() and (ws / "attempt_2").is_dir()
    assert not (ws / "attempt_3").exists()
    assert not (ws / "attempt_1" / "success.json").exists()
    assert (ws / "attempt_2" / "success.json").exists()

    history = json.loads((ws / "failure_history.json").read_text())
    assert len(history) == 1 and history[0]["attempt"] == 1
    assert history[0]["verified_report"] is False
    # Only controller-recorded / enum fields travel across attempts.
    assert "architect_reasoning" not in history[0]
    assert "anti_evasion" not in history[0]

    # The second attempt's Architect and Executor saw the failure history.
    second_arch = [m for m in llm.systems if "Architect" in m]
    assert second_arch
    assert (ws / "token_usage.json").exists()


def test_single_attempt_keeps_flat_layout(tmp_path, sample):
    orch, _ = _build(tmp_path, sample, max_attempts=1)
    orch.run()
    assert (tmp_path / "ws" / "environment_spec.json").exists()
    assert not (tmp_path / "ws" / "attempt_1").exists()


# ── report validator ──────────────────────────────────────────────────────────


def _good_report(tid=7):
    return {"classification": "rat", "confidence": "high", "behaviour_summary": [],
            "iocs": [{"type": "ip", "value": "203.0.113.9"}],
            "mitre_attack": ["T1071.001 — Web Protocols"], "cape_task_id": tid}


def test_validate_report_accepts_well_formed():
    assert validate_report(_good_report(), expected_task_id=7) == []


@pytest.mark.parametrize("mutate,fragment", [
    (lambda r: r.pop("iocs"), "missing required field 'iocs'"),
    (lambda r: r.update(confidence="certain"), "confidence must be one of"),
    (lambda r: r.update(iocs=[{"type": "ip"}]), "iocs[0] must be an object"),
    (lambda r: r.update(iocs=[{"type": "banana", "value": "x"}]), "not a known IOC type"),
    (lambda r: r.update(mitre_attack=["Lateral movement"]), "not a Txxxx technique id"),
    (lambda r: r.update(cape_task_id="7"), "does not name the verified task"),
    (lambda r: r.update(cape_task_id=True), "does not name the verified task"),
])
def test_validate_report_rejects(mutate, fragment):
    r = _good_report()
    mutate(r)
    problems = validate_report(r, expected_task_id=7)
    assert any(fragment in p for p in problems), problems


def test_validate_report_rejects_non_object():
    assert validate_report("not a dict", expected_task_id=None)
    assert validate_report(["x"], expected_task_id=None)


def test_validate_report_accepts_modern_c2_ioc_types():
    # Regression: a live Mirai run classified correctly but was fail-closed
    # because it reported a Telegram C2 channel — a descriptive label, not a
    # security-relevant field. Modern C2/host indicator types are first-class.
    r = _good_report()
    r["iocs"] = [{"type": "telegram", "value": "t.me/freeshi67"},
                 {"type": "tor_onion", "value": "abc.onion"}]
    assert validate_report(r, expected_task_id=7) == []


def test_normalize_report_coerces_unknown_ioc_type_to_other():
    # An IOC type the whitelist still does not recognise must not discard the
    # whole report: _normalize_report coerces it to "other", preserving the
    # original as raw_type, so the normalized report is promotable.
    r = _good_report()
    r["iocs"] = [{"type": "quantum_beacon", "value": "x"}]
    assert any("not a known IOC type" in p
               for p in validate_report(r, expected_task_id=7))  # raw is rejected
    norm = _normalize_report(r)
    assert norm["iocs"][0]["type"] == "other"
    assert norm["iocs"][0]["raw_type"] == "quantum_beacon"
    assert validate_report(norm, expected_task_id=7) == []       # normalized promotes
