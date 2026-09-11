#!/usr/bin/env python3
"""
Security regression tests for the M2 controller wiring.

Properties, not existence checks (SG-TEST-01):
  SG-CTL-03   a role cannot call a tool outside its table
  SG-DATA-01  query_json cannot read outside the workspace
  SG-DATA-02  the analyze_sample carve-out follows the pinned inode, not a path string
  SG-DATA-03  cape_submit uploads the pinned sample regardless of the argument
  SG-AUTH-01  cape_status / cape_fetch_report refuse ids this run did not submit
  SG-CONC-01  cape_vm_start needs the lease; unknown VMs are refused
  SG-NET-01   the route field reaches the CAPE client
  SG-LOG-01   redaction covers Authorization: Token, cookies, URL userinfo, bare keys
  SG-CTL-02   analysis.report is only promoted through the validator
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from core.agent_loop import AgentLoop  # noqa: E402
from core.env_spec import EnvironmentSpec  # noqa: E402
from core.redact import redact  # noqa: E402
from core.run_context import RunContext  # noqa: E402
from core.spec_policy import ROLE_TOOLS, tool_allowed  # noqa: E402


class _Log:
    def __getattr__(self, name):
        return lambda *a, **k: None


class _CAPE:
    def __init__(self):
        self.submits = []

    def submit_file(self, path, options=None):
        self.submits.append((path, dict(options or {})))
        return 4242 + len(self.submits)

    def get_task_status(self, task_id):
        return "reported"

    def get_report(self, task_id):
        return {"target": {"file": {"sha256": "x"}}}


@pytest.fixture()
def env(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sample = tmp_path / "outside" / "sample.bin"
    sample.parent.mkdir()
    sample.write_bytes(b"MZ canary")
    spec = EnvironmentSpec(ws, "m2")
    ctx = RunContext(run_id="m2", workspace=ws)
    ctx.bind_sample(sample)
    ctx.set_route_policy("inetsim")
    return ws, sample, spec, ctx


def _loop(spec, ctx, role="Executor", cape=None):
    return AgentLoop(llm=None, system_prompt="x", spec=spec, log=_Log(),
                     agent_name=role, cape_client=cape, ctx=ctx)


# ── SG-CTL-03 ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("role,tool", [
    ("Scout", "cape_submit"), ("Scout", "cape_vm_start"),
    ("Architect", "cape_submit"), ("Architect", "fetch_url"),
    ("Analyst", "cape_submit"), ("Analyst", "clone_repo"), ("Analyst", "cape_vm_start"),
    ("Executor", "fetch_url"), ("Executor", "clone_repo"), ("Executor", "mb_lookup"),
])
def test_role_cannot_reach_foreign_tool(env, role, tool):
    ws, sample, spec, ctx = env
    assert not tool_allowed(role, tool)
    result = _loop(spec, ctx, role=role, cape=_CAPE())._execute_tool({"tool": tool})
    assert "not available to the" in result["result"]


def test_unknown_role_gets_no_tools_but_finish(env):
    ws, sample, spec, ctx = env
    assert not tool_allowed("Interloper", "read_spec")
    assert tool_allowed("Interloper", "finish")
    r = _loop(spec, ctx, role="Interloper")._execute_tool({"tool": "read_spec"})
    assert "not available" in r["result"]


def test_every_role_table_is_a_subset_of_dispatchable_tools():
    known = {"analyze_sample", "read_spec", "update_spec", "append_spec", "read_file",
             "write_file", "fetch_url", "clone_repo", "mb_lookup", "cape_submit",
             "cape_status", "cape_fetch_report", "cape_service_check", "cape_vm_start",
             "query_json", "log_decision", "log_observation", "finish"}
    for role, tools in ROLE_TOOLS.items():
        assert tools <= known, (role, tools - known)


# ── SG-DATA-01 ────────────────────────────────────────────────────────────────


def test_query_json_refuses_paths_outside_workspace(env, tmp_path):
    ws, sample, spec, ctx = env
    secret = tmp_path / "llm.yaml"
    secret.write_text('{"api_key": "sk-ant-secret"}')
    loop = _loop(spec, ctx, role="Analyst")
    out = loop._query_json(str(secret), "", 5)
    assert out.startswith("ERROR") and "outside the run workspace" in out
    assert "sk-ant" not in out


def test_query_json_reads_inside_workspace(env):
    ws, sample, spec, ctx = env
    (ws / "r.json").write_text(json.dumps({"signatures": [1, 2, 3]}))
    out = _loop(spec, ctx, role="Analyst")._query_json("r.json", "signatures", 5)
    assert "length=3" in out


# ── SG-DATA-02 ────────────────────────────────────────────────────────────────


def test_analysis_path_carveout_follows_pinned_inode_not_spec(env, tmp_path):
    ws, sample, spec, ctx = env
    loop = _loop(spec, ctx, role="Scout")
    # The pinned file, outside the workspace, is readable.
    assert loop._confine_analysis_path(str(sample)) == sample.resolve()
    # A spec rewrite pointing at another outside file does not widen it.
    other = tmp_path / "outside" / "etc_shadow"
    other.write_bytes(b"root:x")
    spec.set("sample.path", str(other), actor="controller")
    with pytest.raises(ValueError):
        loop._confine_analysis_path(str(other))


# ── SG-DATA-03 / SG-NET-01 / SG-CTL-01 ────────────────────────────────────────


def test_cape_submit_uploads_pinned_sample_and_route_and_records_receipt(env):
    ws, sample, spec, ctx = env
    cape = _CAPE()
    loop = _loop(spec, ctx, cape=cape)
    out = loop._tool_cape_submit({"sample_path": "/etc/passwd", "package": "exe"})
    assert out.startswith("OK")
    path, options = cape.submits[0]
    assert Path(path) == sample.resolve()
    assert options["route"] == "inetsim"
    assert "ignored" in out
    receipt = ctx.latest_task()
    assert receipt is not None and receipt.task_id == 4243 and receipt.pass_number == 1
    assert spec.get("cape_submission.pass1_task_id") == 4243
    assert spec.get("executor.passes_completed") == 1


def test_submission_warns_model_about_unapplied_options(env):
    ws, sample, spec, ctx = env
    cape = _CAPE()
    cape.submission_warnings = lambda task_id: ["force-sleepskip=1", "memory=True"]
    out = _loop(spec, ctx, cape=cape)._tool_cape_submit({"sample_path": str(sample), "package": "exe"})
    assert "did NOT apply" in out and "force-sleepskip=1" in out and "memory=True" in out
    assert ctx.latest_task() is not None


def test_cape_submit_without_bound_sample_is_refused(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    spec = EnvironmentSpec(ws, "m2")
    ctx = RunContext(run_id="m2", workspace=ws)
    cape = _CAPE()
    out = _loop(spec, ctx, cape=cape)._tool_cape_submit({"sample_path": str(ws)})
    assert out.startswith("ERROR") and not cape.submits


def test_task_cap_is_reported_not_fatal(env):
    ws, sample, spec, ctx = env
    cape = _CAPE()
    loop = _loop(spec, ctx, cape=cape)
    for _ in range(8):
        assert loop._tool_cape_submit({"package": "exe"}).startswith("OK")
    out = loop._tool_cape_submit({"package": "exe"})
    assert out.startswith("ERROR") and "ledger refused" in out
    assert len(ctx.tasks) == 8


# ── SG-AUTH-01 ────────────────────────────────────────────────────────────────


def test_status_and_report_refuse_foreign_task_ids(env):
    ws, sample, spec, ctx = env
    cape = _CAPE()
    loop = _loop(spec, ctx, cape=cape)
    loop._tool_cape_submit({"package": "exe"})
    mine = ctx.latest_task().task_id
    assert loop._tool_cape_status({"task_id": mine}).startswith("task_id=")
    for foreign in (mine + 1, mine - 1, 1, "1; id", True, None):
        assert loop._tool_cape_status({"task_id": foreign}).startswith("ERROR"), foreign
        assert loop._tool_cape_fetch_report({"task_id": foreign}).startswith("ERROR"), foreign


# ── SG-CONC-01 ────────────────────────────────────────────────────────────────


def test_vm_start_needs_lease_and_allowlisted_name(env, monkeypatch):
    ws, sample, spec, ctx = env
    loop = _loop(spec, ctx)
    ran = []
    monkeypatch.setattr("core.agent_loop.subprocess.run",
                        lambda *a, **k: ran.append(a) or type("P", (), {"stdout": "ok", "stderr": "", "returncode": 0})())
    assert loop._tool_cape_vm_start("cuckoo1").startswith("ERROR")        # no lease
    assert loop._tool_cape_vm_start("evil-vm").startswith("ERROR")        # not allowlisted
    assert not ran
    ctx.acquire_vm_lease("cuckoo1", 60)
    assert loop._tool_cape_vm_start("cuckoo2_linux").startswith("ERROR")  # wrong VM
    assert loop._tool_cape_vm_start("cuckoo1") == "ok"
    assert len(ran) == 1 and "bash" not in ran[0][0]


# ── SG-LOG-01 ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("line", [
    "Authorization: Token 0123456789abcdef0123456789abcdef01234567",
    "Authorization: Bearer eyJhbGciOi",
    "Authorization: Basic dXNlcjpwYXNz",
    "Cookie: sessionid=abc123; csrftoken=def",
    "Set-Cookie: sessionid=abc123",
    "X-Api-Key: 0123456789abcdef",
    "curl https://user:hunter2@cape.example/apiv2/",
    "using sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "key AIzaSyA0123456789abcdefghijklmnopqrstuv",
])
def test_redaction_covers_token_schemes(line):
    out = redact(line)
    assert "[REDACTED]" in out
    for secret in ("0123456789abcdef", "eyJhbGciOi", "dXNlcjpwYXNz", "abc123",
                   "hunter2", "ABCDEFGHIJKLMNOP", "0123456789abcdefghijklmnopqrstuv"):
        assert secret not in out, out


def test_redaction_keeps_the_label_and_url_shape():
    assert redact("Authorization: Token abc") == "Authorization: Token [REDACTED]"
    assert redact("https://u:p@h/x") == "https://u:[REDACTED]@h/x"


# ── SG-CTL-02: promotion only via the validator ──────────────────────────────


def test_analyst_cannot_write_report_directly(env):
    ws, sample, spec, ctx = env
    loop = _loop(spec, ctx, role="Analyst")
    r = loop._execute_tool({"tool": "update_spec", "key": "report", "value": {"classification": "x"}})
    assert r["result"].startswith("REFUSED")
    assert spec.get("report") is None
    r = loop._execute_tool({"tool": "update_spec", "key": "analysis.report",
                            "value": {"classification": "x"}})
    assert r["result"].startswith("OK")
