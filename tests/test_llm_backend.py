#!/usr/bin/env python3
"""
core/llm_backend.py — the properties the evaluation depends on.

  * temperature / seed from config reach the request, and are recorded
  * error classification: 429 backs off, 401 raises at once, "generate"
    in a message is not a rate limit
  * cache tokens are counted
  * an empty completion is retried and its tokens are still counted
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from core.llm_backend import LLMClient, LLMConfig, classify_error  # noqa: E402


class _Exc(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        if status is not None:
            self.status_code = status


class _Usage:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _OpenAIFake:
    """Records kwargs; replays a scripted list of responses/exceptions."""

    def __init__(self, script):
        self.script = list(script)
        self.kwargs = []
        self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.kwargs.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        text, prompt, completion, cached = item
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=text))],
            usage=_Usage(prompt_tokens=prompt, completion_tokens=completion,
                         prompt_tokens_details=_Usage(cached_tokens=cached)),
        )


class _AnthropicFake:
    def __init__(self, script):
        self.script = list(script)
        self.kwargs = []
        self.messages = types.SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.kwargs.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        text, inp, out, cr, cw = item
        return types.SimpleNamespace(
            content=[types.SimpleNamespace(type="text", text=text)],
            usage=_Usage(input_tokens=inp, output_tokens=out,
                         cache_read_input_tokens=cr, cache_creation_input_tokens=cw),
        )


def _client(backend, fake, **kw):
    return LLMClient(backend=backend, model="m", api_key="k", client=fake, **kw)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("core.llm_backend.time.sleep", lambda s: None)


# ── sampling parameters ───────────────────────────────────────────────────────


def test_temperature_and_seed_reach_openai_request_and_usage():
    fake = _OpenAIFake([("hi", 10, 2, 4)])
    c = _client("openai_compatible", fake, temperature=0.0, seed=7)
    assert c.chat("sys", [{"role": "user", "content": "x"}]) == "hi"
    sent = fake.kwargs[0]
    assert sent["temperature"] == 0.0 and sent["seed"] == 7
    assert sent["max_tokens"] == 4096
    u = c.get_usage()
    assert u["temperature"] == 0.0 and u["seed"] == 7
    assert u["cache_read_tokens"] == 4 and u["input_tokens"] == 10


def test_openai_backend_uses_max_completion_tokens():
    fake = _OpenAIFake([("hi", 1, 1, 0)])
    _client("openai", fake).chat("s", [])
    assert "max_completion_tokens" in fake.kwargs[0]


def test_provider_default_when_temperature_unset():
    fake = _OpenAIFake([("hi", 1, 1, 0)])
    _client("openai", fake).chat("s", [])
    assert "temperature" not in fake.kwargs[0] and "seed" not in fake.kwargs[0]


def test_anthropic_temperature_and_cache_tokens():
    fake = _AnthropicFake([("ok", 100, 5, 60, 30)])
    c = _client("anthropic", fake, temperature=0.2)
    assert c.chat("s", []) == "ok"
    assert fake.kwargs[0]["temperature"] == 0.2
    u = c.get_usage()
    assert (u["cache_read_tokens"], u["cache_write_tokens"]) == (60, 30)


# ── error classification ──────────────────────────────────────────────────────


def test_generate_in_message_is_not_a_rate_limit():
    assert classify_error(_Exc("failed to generate completion")) == "retry"
    assert classify_error(_Exc("moderate load, try later")) == "retry"


def test_status_codes_decide():
    assert classify_error(_Exc("x", 429)) == "rate_limit"
    assert classify_error(_Exc("x", 401)) == "fatal"
    assert classify_error(_Exc("x", 400)) == "fatal"
    assert classify_error(_Exc("x", 503)) == "retry"


def test_quota_cycle_detected():
    assert classify_error(_Exc("access_terminated_error: quota will refresh")) == "quota_cycle"


def test_401_raises_immediately_without_retries():
    fake = _OpenAIFake([_Exc("invalid api key", 401), ("never", 1, 1, 0)])
    c = _client("openai", fake)
    with pytest.raises(_Exc):
        c.chat("s", [])
    assert len(fake.kwargs) == 1
    assert c.get_usage()["retries"] == 0
    assert c.get_usage()["requests"] == 1


def test_429_backs_off_then_succeeds():
    fake = _OpenAIFake([_Exc("slow down", 429), _Exc("slow down", 429), ("ok", 1, 1, 0)])
    c = _client("openai", fake)
    assert c.chat("s", []) == "ok"
    assert len(fake.kwargs) == 3


def test_empty_completion_is_retried_and_counted():
    fake = _OpenAIFake([("", 50, 0, 0), ("ok", 5, 1, 0)])
    c = _client("openai", fake)
    assert c.chat("s", []) == "ok"
    u = c.get_usage()
    assert u["input_tokens"] == 55 and u["calls"] == 1 and u["retries"] == 1


def test_empty_completion_grows_max_tokens_on_retry():
    # Regression: a reasoning model returns empty content when the budget is
    # spent on reasoning; retrying with the SAME budget hits the same wall (it
    # lost two whole samples in the first live batch). Each empty retry must
    # grow the token budget, bounded, so the retry can actually emit an answer.
    fake = _OpenAIFake([("", 50, 0, 0), ("", 50, 0, 0), ("ok", 5, 1, 0)])
    c = _client("openai_compatible", fake)
    assert c.chat("s", [], max_tokens=4096) == "ok"
    sent = [k["max_tokens"] for k in fake.kwargs]
    assert sent == [4096, 8192, 16384]  # first at request, then doubled per empty


def test_quota_cycle_without_wait_configured_raises():
    fake = _OpenAIFake([_Exc("access_terminated_error: quota exceeded")])
    with pytest.raises(_Exc):
        _client("openai", fake).chat("s", [])


def test_quota_cycle_with_wait_retries(monkeypatch):
    slept = []
    monkeypatch.setattr("core.llm_backend.time.sleep", lambda s: slept.append(s))
    fake = _OpenAIFake([_Exc("access_terminated_error: quota exceeded"), ("ok", 1, 1, 0)])
    c = _client("openai", fake, quota_cycle_wait_s=2400, retry_budget_s=3000)
    assert c.chat("s", []) == "ok"
    assert slept == [2400]


# ── config ────────────────────────────────────────────────────────────────────


def test_from_yaml_reads_sampling_keys(tmp_path, caplog):
    p = tmp_path / "llm.yaml"
    p.write_text("backend: openai\nmodel: gpt\napi_key: k\ntemperature: 0.7\nseed: 3\n"
                 "max_retries: 2\nmalwarebazaar_api_key: zzz\n")
    cfg = LLMConfig.from_yaml(str(p))
    assert cfg.temperature == 0.7 and cfg.seed == 3 and cfg.max_retries == 2
    assert "malwarebazaar_api_key" in caplog.text        # flagged as ignored
