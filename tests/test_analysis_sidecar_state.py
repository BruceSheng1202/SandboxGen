"""Benign regressions for analysis sidecars sharing the controller workspace."""

import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from core import agent_loop
from core.agent_loop import AgentLoop, run_analyze_op_standalone
from core.env_spec import EnvironmentSpec
from core.workflow_log import WorkflowLog


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_loop, "_ANALYZE_IN_CONTAINER", False)
    monkeypatch.setenv("AMSA_SKIP_SAMPLE_SANDBOX", "1")
    workspace = tmp_path / "workspace"
    sample = tmp_path / "benign.txt"
    sample.write_text("benign fixture, not executable\n")
    spec = EnvironmentSpec(workspace, "controller-run")
    spec.set("sample.path", str(sample), actor="controller")
    spec.set("sample.format", "PE", actor="controller")
    spec.set("cape_submission.package", "exe", actor="controller")
    spec.set("cape_submission.backend_capabilities", {"backend": "qemu-tcg"}, actor="controller")
    return workspace, sample, spec


@pytest.mark.parametrize("operation,missing", [
    ("identify", False), ("identify", True), ("unsupported_operation", False),
])
def test_sidecar_preserves_disk_and_memory_state(state, operation, missing):
    workspace, sample, spec = state
    spec_file = workspace / "environment_spec.json"
    before = spec_file.read_bytes()
    before_stat = spec_file.stat()
    target = workspace / "missing.txt" if missing else sample

    result = run_analyze_op_standalone(operation, target, {}, workspace, sample)

    assert ("sha256=" in result) if operation == "identify" and not missing else result.startswith("ERROR")
    assert spec_file.read_bytes() == before
    assert spec_file.stat().st_ino == before_stat.st_ino
    assert spec_file.stat().st_mtime_ns == before_stat.st_mtime_ns
    assert json.loads(spec.to_json()) == json.loads(before)


def test_sidecar_does_not_create_a_spec(state):
    workspace, sample, _ = state
    spec_file = workspace / "environment_spec.json"
    spec_file.unlink()
    assert "sha256=" in run_analyze_op_standalone("identify", sample, {}, workspace, sample)
    assert not spec_file.exists()


def test_read_spec_and_read_file_agree_after_repeated_operations(state):
    workspace, sample, spec = state
    loop = AgentLoop(None, "x", spec, WorkflowLog(workspace, "test"), "Architect")
    for _ in range(3):
        assert "sha256=" in run_analyze_op_standalone("identify", sample, {}, workspace, sample)
        memory = loop._execute_tool({"tool": "read_spec"})["result"]
        disk = loop._execute_tool({"tool": "read_file", "path": "environment_spec.json"})["result"]
        assert json.loads(memory) == json.loads(disk)


def test_sidecar_extracts_only_to_requested_workspace_destination(state, tmp_path):
    workspace, sample, _ = state
    before = (workspace / "environment_spec.json").read_bytes()
    archive = workspace / "benign.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("hello.txt", "benign data")
    result = run_analyze_op_standalone("zip_extract", archive, {"dest": "unpacked"}, workspace, sample)
    assert result.startswith("OK")
    assert (workspace / "unpacked" / "hello.txt").read_text() == "benign data"
    refused = run_analyze_op_standalone("zip_extract", archive, {"dest": str(tmp_path / "escape")}, workspace, sample)
    assert refused.startswith("ERROR")
    assert not (tmp_path / "escape").exists()
    assert (workspace / "environment_spec.json").read_bytes() == before


@pytest.mark.parametrize("symlink", [False, True])
def test_sidecar_cannot_read_unbound_external_file(state, tmp_path, symlink):
    workspace, sample, _ = state
    outside = tmp_path / "unbound.txt"
    outside.write_text("not the selected input")
    target = outside
    if symlink:
        target = workspace / "outside-link"
        target.symlink_to(outside)
    result = run_analyze_op_standalone("identify", target, {}, workspace, sample)
    assert result.startswith("ERROR")
    assert "outside the run workspace" in result


@pytest.mark.parametrize("operation,mode", [
    ("identify", "ro"), ("pe_exports", "ro"), ("pcap_dns_queries", "ro"),
    ("zip_extract", "rw"), ("archive_extract", "rw"), ("apktool_unpack", "rw"),
])
def test_container_mount_mode_and_isolation(state, monkeypatch, operation, mode):
    workspace, sample, spec = state
    loop = AgentLoop(None, "x", spec, WorkflowLog(workspace, "test"), "Scout")
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        request = json.loads(Path(argv[-1]).read_text())
        assert request["workspace"] == str(workspace)
        assert request["sample_path"] == str(sample)
        return SimpleNamespace(returncode=0, stdout="fixture result", stderr="")

    monkeypatch.setattr(agent_loop.subprocess, "run", fake_run)
    assert loop._run_operation_in_container(operation, sample, {}) == "fixture result"
    argv = seen[0]
    assert f"{workspace}:{workspace}:{mode}" in argv
    assert f"{sample}:{sample}:ro" in argv
    assert argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv and "--cap-drop=ALL" in argv
    assert "no-new-privileges" in argv
    assert not list((workspace / ".analyze").glob("req_*.json"))


def test_analyst_can_write_standalone_report(state):
    workspace, _, spec = state
    log = WorkflowLog(workspace, "test")
    loop = AgentLoop(None, "x", spec, log, "Analyst")
    body = '{"classification":"unknown"}'
    result = loop._execute_tool({"tool": "write_file", "path": "analysis_report.json", "content": body})
    assert result["result"].startswith("OK")
    assert (workspace / "analysis_report.json").read_text() == body


@pytest.mark.parametrize("tool", ["read_file", "write_file"])
def test_failed_file_calls_leave_a_diagnostic_without_content(state, tool):
    workspace, _, spec = state
    log = WorkflowLog(workspace, "test")
    loop = AgentLoop(None, "x", spec, log, "Analyst")
    call = {"tool": tool, "path": "../outside.json", "content": "DO_NOT_LOG_REPORT_CONTENT"}
    result = loop._execute_tool(call)
    assert result["result"].startswith("ERROR")
    failures = [e for e in log._entries if e["level"] == "ERROR"]
    assert failures
    assert tool in failures[0]["message"]
    assert "outside the run workspace" in failures[0]["message"]
    assert "DO_NOT_LOG_REPORT_CONTENT" not in json.dumps(log._entries)
