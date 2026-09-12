"""Regressions for tool parsing, bounded recovery, and completion budgets."""

from __future__ import annotations

import sys
import copy
import json
from pathlib import Path

import pytest


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from core.agent_loop import AgentLoop  # noqa: E402


class _Log:
    def __init__(self):
        self.events = []

    def trace(self, agent, event, data):
        self.events.append((event, copy.deepcopy(data)))

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


class _LLM:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.max_tokens = []
        self.requests = []
        self.last_response_metadata = {}

    def chat(self, *, system, messages, max_tokens):
        self.max_tokens.append(max_tokens)
        self.requests.append(copy.deepcopy(messages))
        response = next(self.responses)
        if isinstance(response, tuple):
            response, finish_reason = response
            self.last_response_metadata = {"finish_reason": finish_reason, "max_tokens": max_tokens}
        else:
            self.last_response_metadata = {}
        return response


def _finish(summary="done"):
    return f'<tool_call>{{"tool":"finish","summary":"{summary}"}}</tool_call>'


def test_no_tool_call_grows_completion_budget_before_retry():
    llm = _LLM([("analysis truncated before the call", "length"), _finish()])
    loop = AgentLoop(llm=llm, system_prompt="x", spec=None, log=_Log(),
                     agent_name="Test", min_iterations=0)

    result = loop.run("work")

    assert result["finished"] is True
    assert llm.max_tokens == [8192, 16384]


def test_explicit_smaller_budget_grows_but_stays_bounded():
    llm = _LLM([("no call", "length"), ("still no call", "length"),
                ("again no call", "length"), _finish()])
    loop = AgentLoop(llm=llm, system_prompt="x", spec=None, log=_Log(),
                     agent_name="Test", min_iterations=0, max_tokens=4096)

    result = loop.run("work")

    assert result["finished"] is True
    assert llm.max_tokens == [4096, 8192, 16384, 16384]


def test_completion_budget_above_ceiling_is_clamped():
    llm = _LLM([_finish()])
    loop = AgentLoop(llm=llm, system_prompt="x", spec=None, log=_Log(),
                     agent_name="Test", min_iterations=0, max_tokens=99999)

    assert loop.run("work")["finished"] is True
    assert llm.max_tokens == [16384]


@pytest.mark.parametrize("prefix", [
    'The field starts with "unfinished.\n',
    'The previous partial object starts with {\n',
    'The field is "ready".\n',
    'Unfinished list: [\n',
])
def test_prose_cannot_swallow_a_complete_tool_call(prefix):
    llm = _LLM([prefix + _finish()])
    loop = AgentLoop(llm, "x", None, _Log(), "Test", min_iterations=0)
    assert loop.run("work")["finished"]
    assert len(llm.requests) == 1


def test_multiple_open_tags_and_literal_newlines_remain_supported():
    loop = AgentLoop(None, "x", None, _Log(), "Analyst")
    response = ('<tool_call>{"tool":"log_observation","message":"a\nb"}'
                'Prose with an unfinished {\n'
                '<tool_call>{"tool":"finish","summary":"done"}</tool_call>')
    assert loop._parse_tool_calls(response) == [
        {"tool": "log_observation", "message": "a\nb"},
        {"tool": "finish", "summary": "done"},
    ]


def test_recorded_second_query_survives_incomplete_prose_json():
    # R2 008-5c047137f0216fad, Analyst request 2; only the local path is replaced.
    response = (Path(__file__).parent / "fixtures/glm52_tool_call_after_incomplete_prose.txt").read_text()
    loop = AgentLoop(None, "x", None, _Log(), "Analyst")
    assert loop._parse_tool_calls(response) == [
        {"tool": "query_json", "file": "cape_report_fixture.json", "path": "", "limit": 20},
        {"tool": "query_json", "file": "cape_report_fixture.json", "path": "signatures", "limit": 50},
    ]


@pytest.mark.parametrize("tagged", [True, False])
def test_tool_text_inside_strings_and_nested_objects_is_not_executed(tagged):
    nested = {"tool": "finish", "summary": "must not execute"}
    call = {"tool": "write_file", "path": "notes.json",
            "content": json.dumps({"nested": nested, "quoted": _finish(),
                                   "escaped": 'a \\" brace } [ newline\n'})}
    text = json.dumps(call)
    if tagged:
        text = "<tool_call>" + text + "</tool_call>"
    loop = AgentLoop(None, "x", None, _Log(), "Analyst")
    assert loop._parse_tool_calls(text) == [call]
    assert loop._parse_tool_calls(json.dumps({"value": nested})) == []
    assert loop._parse_tool_calls("<tool_call>" + json.dumps([nested]) + "</tool_call>") == []
    assert loop._last_parse_diagnostics["status"] == "invalid_tool_schema"


@pytest.mark.parametrize("reason", ["stop", "end_turn", None])
def test_format_errors_without_reported_truncation_do_not_grow_budget(reason):
    malformed = '<tool_call>tool": "finish", "summary": "broken"}</tool_call>'
    llm = _LLM([(malformed, reason), _finish()])
    loop = AgentLoop(llm, "x", None, _Log(), "Test", min_iterations=0)
    assert loop.run("work")["finished"]
    assert llm.max_tokens == [8192, 8192]
    assert "malformed or incomplete" in llm.requests[1][-1]["content"]


@pytest.mark.parametrize("response,status", [
    (None, "empty_response"), ("   ", "empty_response"),
    ("I will inspect the file.", "no_tool_call"),
    ('<tool_call>{"tool":"finish",', "malformed_json"),
    ('<tool_call>{"name":"finish","arguments":{}}</tool_call>', "invalid_tool_schema"),
    ('<tool_call>{"tool":"finish"}</tool_call>', "invalid_tool_schema"),
    ('<tool_call>{"tool":[],"summary":"broken"}</tool_call>', "invalid_tool_schema"),
    ('<tool_call>{"tool":"run_command","command":"unused"}</tool_call>', "invalid_tool_schema"),
])
@pytest.mark.parametrize("normal_budget", [30, 60])
def test_repeated_protocol_failures_stop_with_specific_diagnostics(response, status, normal_budget):
    llm = _LLM([(response, "stop")] * 6)
    log = _Log()
    loop = AgentLoop(llm, "x", None, log, "Test", min_iterations=0,
                     max_iterations=normal_budget)
    outcome = loop.run("work")
    assert outcome == {"finished": False, "summary": None, "iterations": 6,
                       "termination_reason": "protocol_stalled"}
    assert llm.max_tokens == [8192] * 6
    assert [data["phase"] for event, data in log.events if event == "request"] == [
        "normal"] * 3 + ["finalisation"] * 3
    recovery = [data for event, data in log.events if event == "protocol_recovery"]
    assert len(recovery) == 6
    assert all(data["diagnostics"]["status"] == status for data in recovery)
    assert not any(event == "tool_result" for event, data in log.events)


def test_accepted_call_resets_consecutive_failure_count():
    observation = '<tool_call>{"tool":"log_observation","message":"fixture"}</tool_call>'
    llm = _LLM(["bad", "bad", observation, "bad", "bad", _finish()])
    log = _Log()
    loop = AgentLoop(llm, "x", None, log, "Analyst", min_iterations=0)
    assert loop.run("work")["finished"]
    assert [data["phase"] for event, data in log.events if event == "request"] == ["normal"] * 6


def test_protocol_limit_is_configurable_and_finalization_can_recover():
    llm = _LLM(["bad", _finish()])
    log = _Log()
    loop = AgentLoop(llm, "x", None, log, "Test", min_iterations=0,
                     max_consecutive_protocol_errors=1)
    assert loop.run("work")["termination_reason"] == "completed"
    assert [data["phase"] for event, data in log.events if event == "request"] == ["normal", "finalisation"]


@pytest.mark.parametrize("prefix", [
    '<tool_call>{"tool":"write_file","content":"unfinished ',
    '<tool_call>{"tool":"write_file","content": ',
])
def test_malformed_outer_call_cannot_promote_a_nested_call(prefix):
    malformed = prefix + _finish()
    llm = _LLM([malformed] * 6)
    log = _Log()
    loop = AgentLoop(llm, "x", None, log, "Analyst", min_iterations=0)
    assert loop.run("work")["termination_reason"] == "protocol_stalled"
    assert not any(event == "tool_result" for event, data in log.events)


def test_xml_path_indices_are_not_misdiagnosed_as_array_tool_calls():
    xml = ('<invoke name="query_json"><parameter name="path">'
           'behavior.syscall_events[300]</parameter></invoke>\n'
           '<invoke name="query_json"><parameter name="path">'
           'behavior.syscall_events[600]</parameter></invoke>')
    llm = _LLM([xml, _finish()])
    log = _Log()
    loop = AgentLoop(llm, "x", None, log, "Analyst", min_iterations=0)
    assert loop.run("work")["finished"]
    diagnostic = next(data["diagnostics"] for event, data in log.events if event == "protocol_recovery")
    assert diagnostic["status"] == "invalid_tool_schema"
    assert len(diagnostic["errors"]) == 1
    assert "XML <invoke>" in diagnostic["errors"][0]
    assert "array" not in diagnostic["errors"][0]


def test_xml_contents_are_never_promoted_to_actions_or_stripped_from_json_strings():
    loop = AgentLoop(None, "x", None, _Log(), "Analyst")
    xml = '<invoke name="example"><parameter name="data">' + _finish("nested") + '</parameter></invoke>'
    assert loop._parse_tool_calls(xml) == []
    assert loop._parse_tool_calls(xml + _finish("actual")) == [{"tool": "finish", "summary": "actual"}]
    call = {"tool": "write_file", "path": "notes.txt", "content": xml}
    assert loop._parse_tool_calls('<tool_call>' + json.dumps(call) + '</tool_call>') == [call]
