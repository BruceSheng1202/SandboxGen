#!/usr/bin/env python3
"""
core/llm_backend.py — LLM Backend

Supports:
  - Anthropic (claude-sonnet-4-6 etc.)
  - OpenAI
  - OpenAI-compatible (Gemini, SiliconFlow, VectorEngine/DeepSeek, etc.)

Single model used across all agents (Scout, Architect, Executor, Analyst).

Config YAML example:
  backend: anthropic
  model:   claude-sonnet-4-6
  api_key: <YOUR_ANTHROPIC_API_KEY>
  temperature: 0.0          # optional; omit to use the provider default
  seed: 12345               # optional; OpenAI-compatible backends only
  request_timeout_s: 120    # read timeout at the baseline token budget
  request_timeout_max_s: 300
  max_attempts: 4          # includes the initial provider request
  retry_budget_s: 1200     # admission budget, including retry waits

Evaluation reproducibility (internal work log, 2026-09-06, section 6.2): the old version read
neither `temperature` nor `seed` although the config template declared one,
classified rate limits by the substring "rate" (which matched "generate" and
"moderate"), retried authentication failures five times, and did not count
prompt-cache tokens. Every one of those made the benchmark numbers either
irreproducible or mis-costed. This version fixes all four and records the
sampling parameters it actually used in `get_usage()` so a result file
carries its own provenance.
"""

import os
import time
import logging
import copy
import hashlib
import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

from core.redact import redact

logger = logging.getLogger("amsa")

# Retry edition: some providers (Kimi/Moonshot) suspend the key for the rest
# of a billing cycle with an `access_terminated_error`; the only useful
# reaction is to wait for the cycle to refresh. Off unless configured.
QUOTA_CYCLE_ERROR_MARKERS = ("access_terminated_error", "quota")


@dataclass
class LLMConfig:
    backend:  str = "anthropic"
    model:    str = "claude-sonnet-4-6"
    api_key:  str = ""
    base_url: str = ""
    # USD per million tokens — used only for cost logging, not billing.
    price_input_per_mtok:  float = 0.0
    price_output_per_mtok: float = 0.0
    # Sampling controls. None = provider default, recorded as such.
    temperature: Optional[float] = None
    seed: Optional[int] = None
    # Transport controls.
    request_timeout_s: float = 300.0
    request_timeout_max_s: Optional[float] = None
    request_timeout_reference_tokens: int = 8192
    connect_timeout_s: float = 10.0
    write_timeout_s: float = 30.0
    # Admission budget for one logical request, including attempts and waits.
    # In-flight I/O uses phase timeouts; this is not an interrupting watchdog.
    retry_budget_s: float = 1200.0
    max_attempts: Optional[int] = None
    # Backward-compatible alias: includes the initial attempt.
    max_retries: int = 5
    # Seconds to sleep on a quota-cycle error before retrying; 0 disables
    # (the Retry edition used 40 minutes).
    quota_cycle_wait_s: float = 0.0

    @classmethod
    def from_yaml(cls, path: str) -> "LLMConfig":
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        cfg = cls()
        cfg.backend  = data.get("backend",  cfg.backend)
        cfg.model    = data.get("model",    cfg.model)
        cfg.api_key  = data.get("api_key",  cfg.api_key)
        cfg.base_url = data.get("base_url", cfg.base_url)
        cfg.price_input_per_mtok  = float(data.get("price_input_per_mtok",  cfg.price_input_per_mtok))
        cfg.price_output_per_mtok = float(data.get("price_output_per_mtok", cfg.price_output_per_mtok))
        if data.get("temperature") is not None:
            cfg.temperature = float(data["temperature"])
        if data.get("seed") is not None:
            cfg.seed = int(data["seed"])
        cfg.request_timeout_s = float(data.get("request_timeout_s", cfg.request_timeout_s))
        cfg.max_retries = int(data.get("max_retries", cfg.max_retries))
        if data.get("max_attempts") is not None:
            cfg.max_attempts = int(data["max_attempts"])
            if "max_retries" in data and cfg.max_retries != cfg.max_attempts:
                raise ValueError("max_attempts and legacy max_retries must agree")
            cfg.max_retries = cfg.max_attempts
        for key in ("request_timeout_max_s", "connect_timeout_s", "write_timeout_s", "retry_budget_s"):
            if data.get(key) is not None:
                setattr(cfg, key, float(data[key]))
        cfg.request_timeout_reference_tokens = int(data.get(
            "request_timeout_reference_tokens", cfg.request_timeout_reference_tokens))
        cfg.quota_cycle_wait_s = float(data.get("quota_cycle_wait_s", cfg.quota_cycle_wait_s))
        unknown = set(data) - {
            "backend", "model", "api_key", "base_url", "price_input_per_mtok",
            "price_output_per_mtok", "temperature", "seed", "request_timeout_s",
            "max_retries", "quota_cycle_wait_s",
            "max_attempts", "request_timeout_max_s", "request_timeout_reference_tokens",
            "connect_timeout_s", "write_timeout_s", "retry_budget_s",
        }
        if unknown:
            # SG-CONFIG-01: a key nobody reads is a silent misconfiguration.
            logger.warning("[LLM] llm.yaml keys ignored by this version: %s",
                           ", ".join(sorted(unknown)))
        return cfg


# ── error classification ─────────────────────────────────────────────────────

_RETRIABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}
_FATAL_STATUS = {400, 401, 403, 404, 422}


def _status_code(exc: Exception) -> Optional[int]:
    """HTTP status carried by an SDK exception, when there is one."""
    for attr in ("status_code", "status", "http_status"):
        v = getattr(exc, attr, None)
        if isinstance(v, int):
            return v
    resp = getattr(exc, "response", None)
    v = getattr(resp, "status_code", None)
    return v if isinstance(v, int) else None


def classify_error(exc: Exception) -> str:
    """
    One of: "rate_limit", "quota_cycle", "fatal", "retry".

    Status codes decide when present. The substring fallback is only for
    exceptions that carry no status and is deliberately narrow — the old
    `"rate" in str(e)` matched ordinary words.
    """
    text = str(exc).lower()
    if any(m in text for m in QUOTA_CYCLE_ERROR_MARKERS) and (
        "terminated" in text or "refresh" in text or "exceeded" in text
    ):
        return "quota_cycle"
    code = _status_code(exc)
    if code == 429:
        return "rate_limit"
    if code in _FATAL_STATUS:
        return "fatal"
    if code in _RETRIABLE_STATUS:
        return "retry"
    name = type(exc).__name__.lower()
    if "ratelimit" in name or "rate limit" in text or "rate_limit" in text:
        return "rate_limit"
    if any(k in name for k in ("authentication", "permission", "notfound", "badrequest")):
        return "fatal"
    if "credit" in text or "billing" in text or "insufficient_quota" in text:
        return "fatal"
    if any(k in name for k in ("timeout", "connection", "apistatus", "internalserver", "overloaded")):
        return "retry"
    return "retry"


class RetryBudgetExceeded(TimeoutError):
    """No new provider attempt may start within this logical request's budget."""


def _json_value(value):
    """Public SDK response fields only; never traverse request/client objects."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    if callable(getattr(value, "model_dump", None)):
        return value.model_dump(mode="json")
    # Also supports the small benign SDK fixtures used in offline tests.
    if hasattr(value, "__dict__"):
        return {k: _json_value(v) for k, v in vars(value).items() if not k.startswith("_")}
    return {"unserialized_type": type(value).__name__}


def _request_id(value):
    for key in ("_request_id", "request_id"):
        found = getattr(value, key, None)
        if isinstance(found, str):
            return found
    headers = getattr(getattr(value, "response", None), "headers", {})
    return headers.get("x-request-id") or headers.get("request-id")


def _error_details(exc):
    chain, seen = [], set()
    cause = exc
    while cause is not None and id(cause) not in seen and len(chain) < 8:
        seen.add(id(cause))
        chain.append({"type": type(cause).__name__, "message": redact(str(cause))})
        cause = cause.__cause__ or (None if cause.__suppress_context__ else cause.__context__)
    return {"error_type": type(exc).__name__, "error": redact(str(exc)),
            "status_code": _status_code(exc), "request_id": _request_id(exc),
            "causes": chain, "usage": None, "output_available": False}


def _retry_after(exc):
    headers = getattr(getattr(exc, "response", None), "headers", {})
    for key, scale in (("retry-after-ms", 0.001), ("retry-after", 1.0)):
        raw = headers.get(key)
        if raw is None:
            continue
        try:
            value = float(raw) * scale
        except (TypeError, ValueError):
            try:
                when = parsedate_to_datetime(raw)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                value = (when - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                continue
        if math.isfinite(value) and value >= 0:
            return value
    return None


class LLMClient:
    """Thin wrapper around the Anthropic or OpenAI SDK."""

    def __init__(self, backend: str, model: str, api_key: str, base_url: str = "",
                 price_input_per_mtok: float = 0.0, price_output_per_mtok: float = 0.0,
                 temperature: Optional[float] = None, seed: Optional[int] = None,
                 request_timeout_s: float = 300.0, max_retries: int = 5,
                 quota_cycle_wait_s: float = 0.0, client=None, *,
                 max_attempts: Optional[int] = None,
                 request_timeout_max_s: Optional[float] = None,
                 request_timeout_reference_tokens: int = 8192,
                 connect_timeout_s: float = 10.0, write_timeout_s: float = 30.0,
                 retry_budget_s: float = 1200.0):
        self.backend  = backend
        self.model    = model
        self.api_key  = api_key
        self.base_url = base_url
        self.temperature = temperature
        self.seed = seed
        self.request_timeout_s = float(request_timeout_s)
        self.request_timeout_max_s = float(request_timeout_max_s if request_timeout_max_s is not None
                                           else self.request_timeout_s * 2.5)
        self.request_timeout_reference_tokens = int(request_timeout_reference_tokens)
        self.connect_timeout_s = float(connect_timeout_s)
        self.write_timeout_s = float(write_timeout_s)
        self.retry_budget_s = float(retry_budget_s)
        self.max_retries = int(max_retries if max_attempts is None else max_attempts)
        self.quota_cycle_wait_s = float(quota_cycle_wait_s)
        for name in ("request_timeout_s", "request_timeout_max_s", "connect_timeout_s",
                     "write_timeout_s", "retry_budget_s"):
            if not math.isfinite(getattr(self, name)) or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be finite and positive")
        if self.request_timeout_max_s < self.request_timeout_s:
            raise ValueError("request_timeout_max_s must be >= request_timeout_s")
        if self.max_retries < 1 or self.request_timeout_reference_tokens < 1:
            raise ValueError("max_attempts and request_timeout_reference_tokens must be positive")
        if not math.isfinite(self.quota_cycle_wait_s) or self.quota_cycle_wait_s < 0:
            raise ValueError("quota_cycle_wait_s must be finite and nonnegative")
        # `client` is an injection point for tests; production builds the SDK.
        self._client  = client if client is not None else self._init_client()
        if client is not None and getattr(client, "max_retries", 0) != 0:
            self._client = client.with_options(max_retries=0)

        self.price_input_per_mtok  = price_input_per_mtok
        self.price_output_per_mtok = price_output_per_mtok
        self.total_input_tokens  = 0
        self.total_output_tokens = 0
        self.total_cache_read_tokens  = 0
        self.total_cache_write_tokens = 0
        self.call_count          = 0
        self.retry_count         = 0
        self.request_count       = 0
        self.transport_error_count = 0
        self.empty_response_count = 0
        self.unknown_usage_count = 0
        self.total_latency_s     = 0.0
        self.trace_callback      = None
        self.last_response_metadata = {}
        self._provider_response = None
        self._provider_usage_known = False

    def _read_timeout(self, max_tokens):
        ratio = max_tokens / self.request_timeout_reference_tokens
        # Extra 25% headroom when moving above the baseline token budget.
        # Production: 8192 -> 120s, 16384 -> 300s, with a configured cap.
        scaled = self.request_timeout_s * (ratio * 1.25 if ratio > 1 else 1)
        return min(scaled, self.request_timeout_max_s)

    def _timeout(self, read_timeout, remaining):
        # Use the provider SDK's public Timeout type. The deployed OpenAI SDK
        # uses httpx2, while other SDK versions may use httpx.
        if self.backend == "anthropic":
            from anthropic import Timeout
        else:
            from openai import Timeout
        return Timeout(read=min(read_timeout, remaining),
                       connect=min(self.connect_timeout_s, remaining),
                       write=min(self.write_timeout_s, remaining),
                       pool=min(self.connect_timeout_s, remaining))

    def _trace_attempt(self, data):
        if self.trace_callback is not None:
            self.trace_callback(data)

    def _init_client(self):
        if self.backend == "anthropic":
            import anthropic
            kwargs = {"api_key": self.api_key or os.environ.get("ANTHROPIC_API_KEY", ""),
                      "timeout": self.request_timeout_s,
                      # We do our own retries with classification; the SDK's
                      # built-in retries would multiply the wait.
                      "max_retries": 0}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            return anthropic.Anthropic(**kwargs)
        else:
            import openai
            kwargs = {"api_key": self.api_key or os.environ.get("OPENAI_API_KEY", ""),
                      "timeout": self.request_timeout_s,
                      "max_retries": 0}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            return openai.OpenAI(**kwargs)

    # ── one request ─────────────────────────────────────────────────────

    def _request(self, system: str, messages: list, max_tokens: int, timeout):
        """Returns (text, usage_dict, finish_reason). Raises the SDK exception on
        failure. finish_reason lets chat() tell a budget-exhausted empty
        completion ('length' — reasoning ate the token budget, common for
        reasoning models like glm-5.2) from a genuinely empty one."""
        if self.backend == "anthropic":
            kwargs = dict(model=self.model, max_tokens=max_tokens,
                          system=system, messages=messages, timeout=timeout)
            if self.temperature is not None:
                kwargs["temperature"] = self.temperature
            resp = self._client.messages.create(**kwargs)
            self._provider_response = _json_value(resp)
            self._provider_request_id = _request_id(resp)
            text = None
            for block in (getattr(resp, "content", None) or []):
                if getattr(block, "type", "text") == "text" and getattr(block, "text", None):
                    text = (text or "") + block.text
            u = getattr(resp, "usage", None)
            self._provider_usage_known = (getattr(u, "input_tokens", None) is not None
                                          and getattr(u, "output_tokens", None) is not None)
            usage = {
                "input":       getattr(u, "input_tokens", 0) or 0,
                "output":      getattr(u, "output_tokens", 0) or 0,
                "cache_read":  getattr(u, "cache_read_input_tokens", 0) or 0,
                "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0,
            }
            return text, usage, getattr(resp, "stop_reason", None)

        msgs = [{"role": "system", "content": system}] + messages
        token_param = "max_completion_tokens" if self.backend == "openai" else "max_tokens"
        kwargs = dict(model=self.model, messages=msgs, timeout=timeout, **{token_param: max_tokens})
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.seed is not None:
            kwargs["seed"] = self.seed
        resp = self._client.chat.completions.create(**kwargs)
        self._provider_response = _json_value(resp)
        self._provider_request_id = _request_id(resp)
        choice = resp.choices[0] if getattr(resp, "choices", None) else None
        text = choice.message.content if choice else None
        u = getattr(resp, "usage", None)
        self._provider_usage_known = (getattr(u, "prompt_tokens", None) is not None
                                      and getattr(u, "completion_tokens", None) is not None)
        details = getattr(u, "prompt_tokens_details", None)
        usage = {
            "input":       getattr(u, "prompt_tokens", 0) or 0,
            "output":      getattr(u, "completion_tokens", 0) or 0,
            "cache_read":  getattr(details, "cached_tokens", 0) or 0,
            "cache_write": 0,
        }
        finish = getattr(choice, "finish_reason", None) if choice else None
        return text, usage, finish

    def chat(self, system: str, messages: list,
             max_tokens: int = 4096, retries: Optional[int] = None) -> str:
        """Retry only this request, with frozen messages and bounded admissions.

        ``retries`` and legacy ``max_retries`` both mean total attempts. New
        retries stop when retry_budget_s expires; phase I/O timeouts are capped
        to the remaining budget, but do not constitute a wall-clock watchdog.
        """
        attempts = self.max_retries if retries is None else int(retries)
        if attempts < 1 or max_tokens < 1:
            raise ValueError("attempt count and max_tokens must be positive")
        messages = copy.deepcopy(messages)
        input_sha256 = hashlib.sha256(json.dumps(
            {"system": system, "messages": messages}, ensure_ascii=False,
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        deadline = time.monotonic() + self.retry_budget_s
        cur_max_tokens = int(max_tokens)
        ceil_max_tokens = max(cur_max_tokens, 16384)
        last_exc: Optional[Exception] = None
        self.last_response_metadata = {}

        def exhausted(reason):
            self._trace_attempt({"phase": "exhausted", "reason": reason,
                                 "input_sha256": input_sha256,
                                 "retry_budget_s": self.retry_budget_s})
            raise RetryBudgetExceeded(reason) from last_exc

        def wait_for_retry(attempt, kind, exc=None):
            if kind == "quota_cycle":
                delay = self.quota_cycle_wait_s
            else:
                base = min((15 if kind == "rate_limit" else 5) * 2 ** min(attempt - 1, 10),
                           120 if kind == "rate_limit" else 60)
                delay = base + random.uniform(0, min(5, base * 0.25))
                provider_delay = _retry_after(exc) if exc is not None else None
                if provider_delay is not None:
                    delay = max(delay, provider_delay)
            if delay >= deadline - time.monotonic():
                exhausted("retry wait would exhaust the logical request budget")
            self._trace_attempt({"phase": "retry_wait", "attempt": attempt,
                                 "reason": kind, "delay_s": delay,
                                 "input_sha256": input_sha256})
            logger.warning("[LLM] %s; retrying after %.2fs (attempt %d/%d)",
                           kind, delay, attempt, attempts)
            time.sleep(delay)

        for attempt in range(1, attempts + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                exhausted("logical request budget exhausted before next attempt")
            timeout = self._timeout(self._read_timeout(cur_max_tokens), remaining)
            attempt_config = {"attempt": attempt, "max_attempts": attempts,
                              "max_tokens": cur_max_tokens, "model": self.model,
                              "temperature": self.temperature, "seed": self.seed,
                              "input_sha256": input_sha256,
                              "timeout_s": {k: getattr(timeout, k) for k in ("connect", "read", "write", "pool")},
                              "remaining_budget_s": remaining}
            started = time.monotonic()
            self._provider_response = None
            self._provider_request_id = None
            self._provider_usage_known = False
            self.last_response_metadata = {}
            self.request_count += 1
            if attempt > 1:
                self.retry_count += 1
            self._trace_attempt({"phase": "request", **attempt_config})
            try:
                text, usage, finish = self._request(system, messages, cur_max_tokens, timeout)
            except Exception as e:
                elapsed = time.monotonic() - started
                self.total_latency_s += elapsed
                self.transport_error_count += 1
                self.unknown_usage_count += 1
                last_exc = e
                kind = classify_error(e)
                self._trace_attempt({"phase": "error", **attempt_config,
                                     **_error_details(e), "elapsed_s": elapsed,
                                     "classification": kind})
                if kind == "fatal":
                    logger.error("[LLM] Fatal error (%s): %s", type(e).__name__, redact(str(e)))
                    raise
                if attempt == attempts:
                    raise
                if kind == "quota_cycle" and self.quota_cycle_wait_s == 0:
                    raise
                wait_for_retry(attempt, kind, e)
                continue

            elapsed = time.monotonic() - started
            self.total_latency_s += elapsed
            if not self._provider_usage_known:
                self.unknown_usage_count += 1
            # Include usage for length-limited/empty responses too. Provider
            # reasoning is evidence only: it is never returned as tool content.
            self.total_input_tokens        += usage["input"]
            self.total_output_tokens       += usage["output"]
            self.total_cache_read_tokens   += usage["cache_read"]
            self.total_cache_write_tokens  += usage["cache_write"]
            provider_response = self._provider_response or {}
            self.last_response_metadata = {
                **attempt_config, "finish_reason": finish,
                "usage": usage if self._provider_usage_known else None,
                "usage_available": self._provider_usage_known, "elapsed_s": elapsed,
                "response_id": provider_response.get("id"),
                "request_id": self._provider_request_id}
            self._trace_attempt({"phase": "response", "text": text,
                                 "provider_response": provider_response,
                                 **self.last_response_metadata})
            if not text:
                self.empty_response_count += 1
                last_exc = ValueError(
                    f"LLM returned empty response (model={self.model}, "
                    f"finish_reason={finish!r}). Possible reasoning-budget "
                    f"exhaustion or transient API issue.")
                # A refusal is not a transient transport failure.
                if finish in ("content_filter", "sensitive", "refusal"):
                    raise last_exc
                if attempt == attempts:
                    raise last_exc
                if cur_max_tokens < ceil_max_tokens:
                    cur_max_tokens = min(cur_max_tokens * 2, ceil_max_tokens)
                wait_for_retry(attempt, "empty_response")
                continue
            self.call_count += 1
            return text
        raise RuntimeError(f"LLM failed after {attempts} attempts: {last_exc}")

    def get_usage(self) -> dict:
        """Cumulative token usage / estimated cost for this client's lifetime
        (one LLMClient is shared across all agent stages of a single
        orchestrator run, so this reflects one sample's total)."""
        total_tokens = self.total_input_tokens + self.total_output_tokens
        cost = None
        if self.price_input_per_mtok or self.price_output_per_mtok:
            cost = (
                self.total_input_tokens  / 1_000_000 * self.price_input_per_mtok
                + self.total_output_tokens / 1_000_000 * self.price_output_per_mtok
            )
            cost = round(cost, 6)
        return {
            "model":              self.model,
            "backend":            self.backend,
            "calls":              self.call_count,
            "retries":            self.retry_count,
            "input_tokens":       self.total_input_tokens,
            "output_tokens":      self.total_output_tokens,
            "cache_read_tokens":  self.total_cache_read_tokens,
            "cache_write_tokens": self.total_cache_write_tokens,
            "total_tokens":       total_tokens,
            "cost_usd":           cost if self.unknown_usage_count == 0 else None,
            "known_usage_cost_usd": cost,
            "usage_complete":     self.unknown_usage_count == 0,
            "usage_unknown_requests": self.unknown_usage_count,
            "requests":           self.request_count,
            "transport_errors":   self.transport_error_count,
            "empty_responses":    self.empty_response_count,
            "counter_schema_version": 2,
            "counter_semantics": "calls=accepted nonempty replies; requests=provider attempts; retries=actual additional attempts",
            "latency_s":          round(self.total_latency_s, 3),
            # Provenance for the evaluation: what sampling this run used.
            "temperature":        self.temperature,
            "seed":               self.seed,
            "transport_config": {
                "request_timeout_s": self.request_timeout_s,
                "request_timeout_max_s": self.request_timeout_max_s,
                "request_timeout_reference_tokens": self.request_timeout_reference_tokens,
                "connect_timeout_s": self.connect_timeout_s,
                "write_timeout_s": self.write_timeout_s,
                "retry_budget_s": self.retry_budget_s,
                "max_attempts": self.max_retries,
                "sdk_max_retries": 0},
        }


def build_llm(cfg: LLMConfig, role: str = "heavy") -> LLMClient:
    # role parameter kept for call-site compatibility but ignored
    return LLMClient(
        backend  = cfg.backend,
        model    = cfg.model,
        api_key  = cfg.api_key,
        base_url = cfg.base_url,
        price_input_per_mtok  = cfg.price_input_per_mtok,
        price_output_per_mtok = cfg.price_output_per_mtok,
        temperature = cfg.temperature,
        seed = cfg.seed,
        request_timeout_s = cfg.request_timeout_s,
        max_retries = cfg.max_retries,
        max_attempts = cfg.max_attempts,
        request_timeout_max_s = cfg.request_timeout_max_s,
        request_timeout_reference_tokens = cfg.request_timeout_reference_tokens,
        connect_timeout_s = cfg.connect_timeout_s,
        write_timeout_s = cfg.write_timeout_s,
        retry_budget_s = cfg.retry_budget_s,
        quota_cycle_wait_s = cfg.quota_cycle_wait_s,
    )
