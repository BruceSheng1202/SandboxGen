"""Benign regressions for failures observed in the frozen Season1 campaign."""

import copy
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agents.analyst import AnalystAgent
from core.agent_loop import AgentLoop
from core.env_spec import EnvironmentSpec
from core.llm_backend import LLMClient
from core.report_validation import completion_problems
from core.workflow_log import WorkflowLog


def calls(*items):
    return "\n".join("<tool_call>" + json.dumps(item) + "</tool_call>" for item in items)


FINISH = {"tool": "finish", "summary": "fixture complete"}
REPORT = {"classification": "unknown", "confidence": "low", "cape_task_id": 42,
          "behaviour_summary": ["Insufficient evidence in benign fixture"],
          "iocs": [], "mitre_attack": []}


class Script:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.requests = []
        self.last_response_metadata = {}

    def chat(self, **kwargs):
        self.requests.append(copy.deepcopy(kwargs))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        self.last_response_metadata = {}
        if isinstance(response, tuple):
            response, finish_reason = response
            self.last_response_metadata = {"finish_reason": finish_reason, "max_tokens": kwargs["max_tokens"]}
        return response


def loop_at(workspace, llm=None, role="Architect", **kwargs):
    spec = EnvironmentSpec(workspace, "fixture")
    log = WorkflowLog(workspace, "fixture")
    return AgentLoop(llm, "fixture", spec, log, role, min_iterations=0, **kwargs)


def traces(workspace):
    return [json.loads(line) for line in (workspace / "agent_trace.jsonl").read_text().splitlines()]


def test_full_spec_reaches_model_and_backend_survives_context_trimming(tmp_path):
    llm = Script(calls({"tool": "read_spec"}), calls(FINISH))
    loop = loop_at(tmp_path, llm)
    loop.spec.set("sample.notes", "benign padding " * 550, actor="controller")
    loop.spec.set("cape_submission.backend_capabilities", {"backend": "qemu-tcg", "memory_dump": False}, actor="controller")
    loop.spec.set("cape_submission.available_machines", [{"name": "fixture-linux"}], actor="controller")
    assert len(loop.spec.to_json()) > 7000
    assert loop.run("work")["finished"]
    delivery = llm.requests[1]["messages"][-1]["content"]
    assert json.loads(delivery.split("→ ", 1)[1]) == json.loads(loop.spec.to_json())
    loop.messages = [{"role": "user", "content": "x" * 20000} for _ in range(12)]
    loop.messages = loop._trim_messages(loop.messages)
    assert loop._estimate_chars(loop.messages) <= loop.MAX_CONTEXT_CHARS
    assert "CONTEXT TRUNCATED" in str(loop.messages)
    assert "fixture-linux" in loop._system_with_facts()
    assert '"memory_dump": false' in loop._system_with_facts()


def test_oversize_spec_is_explicitly_navigable_and_file_pages_do_not_repeat(tmp_path):
    loop = loop_at(tmp_path)
    loop.spec.set("sample.notes", "a" * 55000 + "TAIL_EVIDENCE", actor="controller")
    root = json.loads(loop._execute_tool({"tool": "read_spec"})["result"])
    assert root["status"] == "too_large" and "sample" in root["keys"]
    page = json.loads(loop._execute_tool({"tool": "read_spec", "path": "sample.notes", "offset": 55000, "limit": 100})["result"])
    assert page["value"] == "TAIL_EVIDENCE" and page["page"]["next_offset"] is None
    (tmp_path / "fixture.txt").write_text("a" * 4000 + "TAIL_EVIDENCE")
    first = loop._execute_tool({"tool": "read_file", "path": "fixture.txt"})
    assert "next read_file offset=4000" in first["result"]
    assert "next read_file offset=4000" in traces(tmp_path)[-1]["data"]["delivered_result"]
    second = loop._execute_tool({"tool": "read_file", "path": "fixture.txt", "offset": 4000})
    assert second["result"] == "TAIL_EVIDENCE"


def test_query_json_observes_state_updated_after_an_earlier_query(tmp_path):
    loop = loop_at(tmp_path)
    call = {"tool": "query_json", "file": "environment_spec.json", "path": "cape_submission.package"}
    loop.spec.set("cape_submission.package", "exe", actor="controller")
    assert json.loads(loop._execute_tool(call)["result"]) == "exe"
    loop._execute_tool({"tool": "update_spec", "key": "cape_submission.package", "value": "dll"})
    assert json.loads(loop._execute_tool(call)["result"]) == "dll"


@pytest.mark.parametrize("call", [
    {"tool": "write_file"},
    {"tool": "write_file", "arguments": {"path": "analysis_report.json", "content": "{}"}},
    {"tool": "write_file", "path": "analysis_report.json", "content": {}},
    {"tool": "finish"}, {"tool": "finish", "summary": " "},
    {"tool": []}, {"tool": "read_file", "path": "x", "offset": -1},
    {"tool": "read_spec", "limit": True},
])
def test_malformed_model_calls_return_feedback_without_side_effects(tmp_path, call):
    loop = loop_at(tmp_path, role="Analyst")
    result = loop._execute_tool(call)
    assert result["result"].startswith("ERROR:")
    assert not loop.finished and not (tmp_path / "analysis_report.json").exists()
    assert traces(tmp_path)[-1]["data"]["call"] == call


def test_missing_standalone_report_can_be_repaired_by_model_in_same_stage(tmp_path):
    llm = Script(calls({"tool": "update_spec", "key": "analysis.report", "value": REPORT}, FINISH),
                 calls({"tool": "write_file", "path": "analysis_report.json", "content": json.dumps(REPORT)}, FINISH))
    loop = loop_at(tmp_path, llm, "Analyst")
    loop.completion_validator = lambda: completion_problems(loop.spec.get("analysis.report"), tmp_path, 42)
    assert loop.run("produce report")["finished"]
    assert "write_file must create" in llm.requests[1]["messages"][-1]["content"]
    assert json.loads((tmp_path / "analysis_report.json").read_text()) == REPORT
    assert loop.spec.get("analysis.report") == REPORT
    assert traces(tmp_path)[-1]["data"]["termination_reason"] == "completed"


@pytest.mark.parametrize("bad", [
    {**REPORT, "iocs": 1}, {**REPORT, "mitre_attack": 1},
    {**REPORT, "iocs": [{"type": [], "value": "fixture"}]},
    {**REPORT, "cape_task_id": 99},
])
def test_bad_report_structure_is_feedback_not_a_framework_exception(tmp_path, bad):
    (tmp_path / "analysis_report.json").write_text(json.dumps(bad))
    assert completion_problems(bad, tmp_path, 42)


def test_mismatched_or_symlinked_report_cannot_complete(tmp_path):
    target = tmp_path / "analysis_report.json"
    target.write_text(json.dumps({**REPORT, "confidence": "high"}))
    assert "same report" in completion_problems(REPORT, tmp_path, 42)[0]
    target.unlink()
    (tmp_path / "other.json").write_text(json.dumps(REPORT))
    target.symlink_to(tmp_path / "other.json")
    assert completion_problems(REPORT, tmp_path, 42)


def test_analyst_prompt_renders_real_paths_as_valid_json(tmp_path):
    workspace = tmp_path / 'space and "quotes"'
    llm = Script(calls({"tool": "read_spec"}),
                 calls({"tool": "update_spec", "key": "analysis.report", "value": REPORT}),
                 calls({"tool": "write_file", "path": "analysis_report.json", "content": json.dumps(REPORT)}, FINISH))
    loop = loop_at(workspace)
    path = str(workspace / "cape_report_42.json")
    loop.spec.set("pass2.artefacts", {"cape_report": path, "cape_report_task_id": 42}, actor="controller")
    assert AnalystAgent(loop.spec, loop.log, llm, workspace).run()
    prompt = llm.requests[0]["system"]
    assert "{report_path}" not in prompt and "{workspace}" not in prompt
    query = next(json.loads(line) for line in prompt.splitlines() if line.startswith('{"tool": "query_json"'))
    assert query["file"] == path


def test_trace_records_provider_evidence_without_executing_reasoning(tmp_path, monkeypatch):
    monkeypatch.setattr("core.llm_backend.time.sleep", lambda _: None)
    script = iter([(None, "length"), ("VISIBLE_FRAGMENT", "length"),
                   (calls({"tool": "read_spec"}), "stop"), TimeoutError("fixture timeout")])
    requests = []

    def create(**kwargs):
        requests.append(copy.deepcopy(kwargs))
        item = next(script)
        if isinstance(item, Exception):
            raise item
        text, finish = item
        if len(requests) == 3:
            client.max_retries = 1
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content=text, reasoning_content="REASONING_FIXTURE api_key=REASONING_SECRET"),
            finish_reason=finish)], usage=SimpleNamespace(prompt_tokens=11, completion_tokens=13))

    sdk = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    client = LLMClient("openai", "fixture", "not_sent", client=sdk, max_retries=2, temperature=0, seed=42)
    loop = loop_at(tmp_path, client)
    with pytest.raises(TimeoutError):
        loop.run("api_key=FIXTURE_SECRET")
    records = traces(tmp_path)
    attempts = [r["data"] for r in records if r["event"] == "llm_attempt"]
    responses = [r for r in attempts if r["phase"] == "response"]
    assert [r["finish_reason"] for r in responses] == ["length", "length", "stop"]
    assert responses[0]["text"] is None and responses[1]["text"] == "VISIBLE_FRAGMENT"
    assert responses[0]["usage"]["output"] == 13
    assert any(r["event"] == "parsed_calls" and r["data"]["empty"] for r in records)
    assert any(r["event"] == "tool_result" for r in records)
    assert records[-1]["event"] == "request_error"
    assert records[-1]["data"]["error_type"] == "TimeoutError"
    assert client.trace_callback is None
    raw = (tmp_path / "agent_trace.jsonl").read_text()
    assert "FIXTURE_SECRET" not in raw and "REASONING_SECRET" not in raw
    assert "REASONING_FIXTURE" in raw
    assert all("REASONING_FIXTURE" not in str(r["messages"]) for r in requests)
    assert stat.S_IMODE((tmp_path / "agent_trace.jsonl").stat().st_mode) == 0o600
    assert all(r["temperature"] == 0 and r["seed"] == 42 for r in requests)


def test_forced_finalisation_keeps_grown_budget_and_exact_iteration_count(tmp_path):
    llm = Script(("truncated", "length"), ("still truncated", "length"), calls(FINISH))
    loop = loop_at(tmp_path, llm, max_iterations=1)
    result = loop.run("work")
    assert result["finished"] and result["iterations"] == 3
    assert [r["max_tokens"] for r in llm.requests] == [8192, 16384, 16384]
    assert [r["data"]["phase"] for r in traces(tmp_path) if r["event"] == "request"] == ["normal", "finalisation", "finalisation"]


def test_protocol_stall_does_not_waive_report_completion(tmp_path):
    llm = Script(*(["invalid output"] * 3 + [calls(FINISH)] * 3))
    loop = loop_at(tmp_path, llm, role="Analyst",
                   completion_validator=lambda: ["analysis_report.json is missing"])
    result = loop.run("work")
    assert not result["finished"] and result["termination_reason"] == "protocol_stalled"
    assert result["iterations"] == 6
    assert not (tmp_path / "analysis_report.json").exists()
    assert "analysis_report.json is missing" in llm.requests[-1]["messages"][-1]["content"]
