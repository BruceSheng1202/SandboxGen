"""Offline regressions for Season1's length -> enlarged-budget -> timeout chain.

Benign synthetic replies and in-memory HTTP transports; no provider requests.
"""

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from core.agent_loop import AgentLoop
from core.llm_backend import LLMClient, LLMConfig, RetryBudgetExceeded, build_llm
from core.workflow_log import WorkflowLog


def reply(text="ok", finish="stop", **extra):
    return NS(id="response-fixture", _request_id="request-fixture",
              choices=[NS(message=NS(content=text, **extra), finish_reason=finish)],
              usage=NS(prompt_tokens=12273, completion_tokens=8192 if not text else 50,
                       completion_tokens_details=NS(reasoning_tokens=8000 if not text else 20)))


class Clock:
    def __init__(self):
        self.now = 0
        self.waits = []

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


class SDK:
    def __init__(self, script, clock):
        self.script = iter(script)
        self.clock = clock
        self.requests = []
        self.chat = NS(completions=NS(create=self.create))

    def create(self, **kwargs):
        self.requests.append(copy.deepcopy(kwargs))
        elapsed, result = next(self.script)
        self.clock.now += elapsed
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr("core.llm_backend.time.monotonic", lambda: clock.now)
    monkeypatch.setattr("core.llm_backend.time.sleep", clock.sleep)
    monkeypatch.setattr("core.llm_backend.random.uniform", lambda a, b: b / 2)
    return clock


def client(sdk, **kwargs):
    options = dict(request_timeout_s=120, request_timeout_max_s=300, max_attempts=4)
    options.update(kwargs)
    return LLMClient("openai_compatible", "fixture", "not-sent", client=sdk, **options)


def test_empty_length_expands_timeout_and_preserves_stage_budget(clock, tmp_path):
    read = '<tool_call>{"tool":"log_observation","observation":"benign"}</tool_call>'
    finish = '<tool_call>{"tool":"finish","summary":"done"}</tool_call>'
    sdk = SDK([(115.6, reply("", "length", reasoning_content="benign thinking")),
               (220, reply(read)), (5, reply(finish)), (5, reply(finish))], clock)
    c = client(sdk)
    log = WorkflowLog(tmp_path, "fixture")
    loop = AgentLoop(c, "fixture", None, log, "Analyst", min_iterations=0)
    assert loop.run("work")["finished"]
    # New stage shares the client, but not the previous stage's budget floor.
    next_stage = AgentLoop(c, "fixture", None, log, "Scout", min_iterations=0)
    assert next_stage.run("work")["finished"]
    assert [r["max_tokens"] for r in sdk.requests] == [8192, 16384, 16384, 8192]
    assert [r["timeout"].read for r in sdk.requests] == [120, 300, 300, 120]
    assert sdk.requests[0]["messages"] == sdk.requests[1]["messages"]
    assert all("benign thinking" not in str(r["messages"]) for r in sdk.requests)
    records = [json.loads(line) for line in (tmp_path / "agent_trace.jsonl").read_text().splitlines()]
    logical = [r["data"]["max_tokens"] for r in records if r["event"] == "request"]
    assert logical == [8192, 16384, 8192]
    calls = [r for r in records if r["event"] == "tool_result"]
    assert len(calls) == 3  # one observation and two finishes, never reasoning


def test_terminal_timeout_has_four_attempts_three_retries_and_unknown_usage(clock):
    sdk = SDK([(115.6, reply("", "length"))] + [(120, TimeoutError("read timeout"))] * 3, clock)
    c = client(sdk, price_output_per_mtok=1)
    records = []
    c.trace_callback = records.append
    with pytest.raises(TimeoutError, match="read timeout"):
        c.chat("sys", [{"role": "user", "content": "same input"}], max_tokens=8192)
    u = c.get_usage()
    assert (u["requests"], u["retries"], u["empty_responses"], u["transport_errors"]) == (4, 3, 1, 3)
    assert u["output_tokens"] == 8192 and u["usage_unknown_requests"] == 3
    assert u["cost_usd"] is None and u["known_usage_cost_usd"] > 0
    assert not u["usage_complete"] and c.last_response_metadata == {}
    assert u["latency_s"] == 475.6  # failures are included, backoff is excluded
    assert len(clock.waits) == 3 and clock.waits == sorted(clock.waits)
    requests = [r for r in records if r["phase"] == "request"]
    assert len({r["input_sha256"] for r in requests}) == 1
    errors = [r for r in records if r["phase"] == "error"]
    assert all(r["usage"] is None and not r["output_available"] for r in errors)


def test_budget_caps_io_and_prevents_a_retry_after_expiry(clock):
    sdk = SDK([(20, TimeoutError("first")), (20, TimeoutError("last"))], clock)
    c = client(sdk, retry_budget_s=40)
    with pytest.raises(RetryBudgetExceeded):
        c.chat("s", [], max_tokens=8192)
    assert len(sdk.requests) == 2
    assert sdk.requests[0]["timeout"].read == 40
    assert sdk.requests[1]["timeout"].read == pytest.approx(40 - 20 - clock.waits[0])
    assert c.get_usage()["retries"] == 1 and len(clock.waits) == 1


@pytest.mark.parametrize("retry_after, budget, expected_requests", [("20", 100, 2), ("200", 100, 1)])
def test_retry_after_is_respected_without_exceeding_admission_budget(clock, retry_after, budget, expected_requests):
    error = RuntimeError("rate limited")
    error.status_code = 429
    error.response = NS(headers={"retry-after": retry_after, "x-request-id": "rate-fixture"})
    sdk = SDK([(1, error), (1, reply())], clock)
    c = client(sdk, retry_budget_s=budget)
    if expected_requests == 1:
        with pytest.raises(RetryBudgetExceeded):
            c.chat("s", [])
        assert not clock.waits
    else:
        assert c.chat("s", []) == "ok"
        assert clock.waits == [20]
    assert len(sdk.requests) == expected_requests


def test_trace_retains_response_fields_and_exception_cause(clock, tmp_path):
    provider = reply("", "length", reasoning_content="thinking api_key=FIXTURE_SECRET",
                     tool_calls=[{"id": "native-fixture", "function": {"name": "not_executed", "arguments": "{}"}}])
    error = TimeoutError("API timeout")
    error.__cause__ = OSError("socket read timed out")
    sdk = SDK([(1, provider), (1, error)], clock)
    c = client(sdk, max_attempts=2)
    log = WorkflowLog(tmp_path, "fixture")
    c.trace_callback = lambda data: log.trace("Analyst", "llm_attempt", data)
    with pytest.raises(TimeoutError):
        c.chat("s", [], max_tokens=8192)
    raw = (tmp_path / "agent_trace.jsonl").read_text()
    assert "FIXTURE_SECRET" not in raw
    records = [json.loads(line)["data"] for line in raw.splitlines()]
    response = next(r for r in records if r["phase"] == "response")
    message = response["provider_response"]["choices"][0]["message"]
    assert "thinking" in message["reasoning_content"] and message["tool_calls"][0]["id"] == "native-fixture"
    assert response["request_id"] == "request-fixture" and response["response_id"] == "response-fixture"
    assert response["provider_response"]["usage"]["completion_tokens_details"]["reasoning_tokens"] == 8000
    error_record = records[-1]
    assert [e["type"] for e in error_record["causes"]] == ["TimeoutError", "OSError"]
    assert error_record["usage"] is None and error_record["elapsed_s"] == 1


def test_missing_provider_usage_is_unknown_not_a_zero_cost(clock):
    response = reply()
    response.usage = None
    c = client(SDK([(1, response)], clock), price_input_per_mtok=1)
    assert c.chat("s", []) == "ok"
    assert c.last_response_metadata["usage"] is None
    assert not c.get_usage()["usage_complete"] and c.get_usage()["cost_usd"] is None


def test_refusal_is_not_retried(clock):
    sdk = SDK([(1, reply("", "sensitive"))], clock)
    c = client(sdk)
    with pytest.raises(ValueError, match="sensitive"):
        c.chat("s", [])
    assert len(sdk.requests) == 1 and not clock.waits


def test_new_config_alias_and_sampling_are_passed_to_client(tmp_path, monkeypatch):
    p = tmp_path / "llm.yaml"
    p.write_text("backend: openai_compatible\nmodel: fixture\nmax_attempts: 4\n"
                 "request_timeout_s: 120\nrequest_timeout_max_s: 300\n"
                 "request_timeout_reference_tokens: 8192\nconnect_timeout_s: 10\n"
                 "write_timeout_s: 30\nretry_budget_s: 1200\ntemperature: 0\nseed: 42\n")
    monkeypatch.setattr(LLMClient, "_init_client", lambda self: NS())
    c = build_llm(LLMConfig.from_yaml(str(p)))
    assert c.max_retries == 4 and c._read_timeout(16384) == 300
    assert c.temperature == 0 and c.seed == 42
    p.write_text("max_attempts: 4\nmax_retries: 5\n")
    with pytest.raises(ValueError, match="must agree"):
        LLMConfig.from_yaml(str(p))


@pytest.mark.parametrize("kwargs", [
    {"request_timeout_s": 0}, {"request_timeout_s": float("nan")},
    {"request_timeout_max_s": 100}, {"connect_timeout_s": -1},
    {"retry_budget_s": float("inf")}, {"request_timeout_reference_tokens": 0},
    {"max_attempts": 0},
])
def test_invalid_limits_fail_before_any_provider_request(kwargs):
    with pytest.raises(ValueError):
        client(NS(), **kwargs)


@pytest.mark.parametrize("backend", ["openai", "openai_compatible", "anthropic"])
def test_real_sdk_receives_phase_timeouts_and_preserves_response_fields(backend):
    # Validate actual SDK serialization, without network or credentials.
    import httpx2
    import openai
    import anthropic

    requests = []

    def handler(request):
        requests.append(request)
        if backend == "anthropic":
            body = {"id": "msg-fixture", "type": "message", "role": "assistant", "model": "fixture",
                    "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
                    "usage": {"input_tokens": 3, "output_tokens": 2}}
        else:
            body = {"id": "chat-fixture", "object": "chat.completion", "created": 1, "model": "fixture",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok",
                                 "reasoning_content": "benign provider evidence"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}}
        return httpx2.Response(200, json=body, headers={"x-request-id": "header-fixture", "request-id": "header-fixture"})

    with httpx2.Client(transport=httpx2.MockTransport(handler)) as http:
        sdk_class = anthropic.Anthropic if backend == "anthropic" else openai.OpenAI
        sdk = sdk_class(api_key="fixture", base_url="https://fixture.invalid/v1", http_client=http)
        c = LLMClient(backend, "fixture", "fixture", client=sdk,
                      request_timeout_s=120, request_timeout_max_s=300)
        records = []
        c.trace_callback = records.append
        assert c._client.max_retries == 0
        assert c.chat("s", [], max_tokens=16384) == "ok"
    assert len(requests) == 1
    assert requests[0].extensions["timeout"] == {"connect": 10, "read": 300, "write": 30, "pool": 10}
    assert records[-1]["request_id"] == "header-fixture"
    body = json.loads(requests[0].content)
    assert "timeout" not in body and body["model"] == "fixture"
    if backend != "anthropic":
        assert records[-1]["provider_response"]["choices"][0]["message"]["reasoning_content"] == "benign provider evidence"
