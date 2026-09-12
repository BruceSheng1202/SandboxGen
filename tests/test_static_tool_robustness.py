"""Benign regressions for the GLM52/DeepSeek static evidence delivery failures."""

import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from core import agent_loop
from core.agent_loop import AgentLoop, _visible_result
from core.env_spec import EnvironmentSpec
from core.workflow_log import WorkflowLog


@pytest.fixture
def analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_loop, "_ANALYZE_IN_CONTAINER", False)
    monkeypatch.setenv("AMSA_SKIP_SAMPLE_SANDBOX", "1")
    sample = tmp_path / "input.bin"
    sample.write_bytes(b"\0fixture\0")
    workspace = tmp_path / "workspace"
    spec = EnvironmentSpec(workspace, "fixture")
    spec.set("sample.path", str(sample), actor="controller")
    loop = AgentLoop(None, "fixture", spec, WorkflowLog(workspace, "fixture"), "Scout")
    return loop, sample


def run_op(analysis, operation, options=None):
    loop, sample = analysis
    return loop._execute_tool({"tool": "analyze_sample", "operation": operation,
                               "path": str(sample), "options": options})["result"]


def page_body(result):
    body, marker = result.rsplit("\n[PAGE:", 1)
    return body, marker


@pytest.mark.parametrize("header", [b"\x7fELF\0", b"MZ\0"])
def test_strings_pages_reach_tail_evidence_on_both_binary_formats(analysis, header):
    loop, sample = analysis
    records = [f"benign_record_{i:04d}" for i in range(600)] + ["TAIL_EVIDENCE"]
    sample.write_bytes(header + b"\0".join(s.encode() for s in records) + b"\0")
    offset, pages = 0, []
    for _ in range(10):
        result = run_op(analysis, "strings", {"offset": offset, "limit": 8000})
        assert _visible_result("analyze_sample", result) == result
        body, marker = page_body(result)
        assert len(body) <= 4000
        pages.append(body)
        if "EOF" in marker:
            break
        next_offset = int(re.search(r"next_offset=(\d+)", marker).group(1))
        assert next_offset > offset
        offset = next_offset
    else:
        pytest.fail("paging never reached EOF")
    assert len(pages) > 1
    assert "".join(pages) == "\n".join(records) + "\n"
    assert page_body(run_op(analysis, "strings", {"offset": 100000}))[0] == ""


def test_strings_min_length_is_applied_and_utf16_is_pageable(analysis):
    _, sample = analysis
    sample.write_bytes(b"\0short\0LONG_STATIC_NEEDLE\0")
    assert "short" in page_body(run_op(analysis, "strings", {"min_length": 4}))[0]
    longer = page_body(run_op(analysis, "strings", {"min_length": 10}))[0]
    assert "short" not in longer and "LONG_STATIC_NEEDLE" in longer
    assert page_body(run_op(analysis, "strings", {"min_length": 20}))[0] == ""
    expected = "WINDOWS_UTF16_TEXT\nNEXT_STRING\n"
    sample.write_bytes(b"MZ\0\0" + "WINDOWS_UTF16_TEXT\0NEXT_STRING\0".encode("utf-16le"))
    first, marker = page_body(run_op(analysis, "strings_utf16", {"limit": 8}))
    offset = int(re.search(r"next_offset=(\d+)", marker).group(1))
    rest, end = page_body(run_op(analysis, "strings_utf16", {"offset": offset}))
    assert first + rest == expected and "EOF" in end


@pytest.mark.parametrize("header", [b"\x7fELF\0", b"MZ\0"])
def test_grep_returns_binary_matches_and_handles_dash_patterns(analysis, header):
    _, sample = analysis
    sample.write_bytes(header + b"\xff\0-NEEDLE\0https://example.invalid/test\0-needle\0")
    result = run_op(analysis, "grep", {"pattern": "-needle", "limit": 9})
    first, marker = page_body(result)
    assert first == "-NEEDLE\n" + "-"
    offset = int(re.search(r"next_offset=(\d+)", marker).group(1))
    rest, end = page_body(run_op(analysis, "grep", {"pattern": "-needle", "offset": offset}))
    assert first + rest == "-NEEDLE\n-needle\n" and "EOF" in end
    assert "https://example.invalid/test" in run_op(analysis, "grep", {"pattern": "https?://[a-z./]+"})
    assert run_op(analysis, "grep", {"pattern": "absent_value"}) == "(no matches)"
    assert run_op(analysis, "grep", {"pattern": "["}).startswith("ERROR: grep exited")


@pytest.mark.parametrize("operation,options", [
    ("strings", {"output_file": "unused.txt"}),
    ("strings", {"offset": -1}),
    ("strings", {"min_length": True}),
    ("strings", {"min_length": 4097}),
    ("strings_utf16", {"limit": 0}),
    ("grep", {"pattern": ["invalid"]}),
    ("grep", {"pattern": "test", "flags": "-r"}),
    ("identify", {"output": "unused.txt"}),
    ("readelf_sections", {}),
    ("strings", []),
])
def test_invalid_options_are_rejected_before_starting_a_process(analysis, monkeypatch, operation, options):
    loop, _ = analysis
    monkeypatch.setattr(loop, "_run_argv", lambda *a, **k: pytest.fail("invalid operation was executed"))
    assert run_op(analysis, operation, options).startswith("ERROR")
    assert not (loop.spec.workspace / "unused.txt").exists()


def test_container_result_preserves_the_page_cursor_to_model_feedback(analysis, monkeypatch):
    loop, sample = analysis
    sample.write_bytes(b"\0" + b"A" * 5000 + b"\0TAIL_EVIDENCE\0")
    expected = run_op(analysis, "strings")
    assert len(expected) > 4000 and "next_offset=4000" in expected
    monkeypatch.setattr(agent_loop, "_ANALYZE_IN_CONTAINER", True)
    monkeypatch.setattr(agent_loop.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=0, stdout=expected, stderr=""))
    assert run_op(analysis, "strings") == expected
    events = [json.loads(line) for line in (loop.spec.workspace / "agent_trace.jsonl").read_text().splitlines()]
    assert events[-1]["data"]["delivered_result"] == expected
    truncated = _visible_result("analyze_sample", "X" * 10000)
    assert "TRUNCATED" in truncated
    assert _visible_result("analyze_sample", truncated) == truncated


@pytest.mark.parametrize("role,download,enabled", [
    ("Scout", False, False), ("Scout", True, True), ("Analyst", True, False),
])
def test_prompt_network_availability_matches_runtime_policy(analysis, role, download, enabled):
    base, _ = analysis
    ctx = SimpleNamespace(allow_sample_download=download)
    loop = AgentLoop(None, "fixture", base.spec, base.log, role, ctx=ctx)
    contract = loop.system_prompt.split("AUTHORITATIVE TOOL CONTRACT", 1)[1]
    assert ('"tool": "mb_lookup"' in contract) is enabled
    assert ('"tool": "fetch_url"' in contract) is enabled
    if not enabled:
        assert "OFFLINE" in contract
        result = loop._execute_tool({"tool": "mb_lookup", "sha256": "fixture"})["result"]
        assert result.startswith("ERROR")
    assert "read_file is limited to the run workspace" in contract


def test_yara_execution_failure_is_not_reported_as_no_matches(analysis, tmp_path, monkeypatch):
    loop, _ = analysis
    (tmp_path / "fixture.yar").write_text("rule fixture { condition: false }")
    monkeypatch.setattr(agent_loop, "_YARA_RULES_DIR", str(tmp_path))
    monkeypatch.setattr(loop, "_run_argv", lambda *a, **k: "ERROR: yara not available on this image")
    assert run_op(analysis, "yara_scan") == "ERROR: yara not available on this image"
