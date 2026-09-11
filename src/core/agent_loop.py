#!/usr/bin/env python3
"""
core/agent_loop.py — Agentic Execution Loop

The core engine used by all four agents. Each agent has:
  - A system prompt describing its goal and reasoning approach
  - An initial message with the task
  - Access to a fixed set of typed tools, described below — no general-
    purpose shell (CTL-01: the old run_shell primitive has been removed)

The agent picks from the fixed tool set for each step of its reasoning.
It writes its findings to the Environment Spec via update_spec.

Tool calls available to every agent:
  analyze_sample(operation, path, options={})
                                   — CTL-01 fix: a fixed allowlist of static-
                                     analysis operations (file identification,
                                     strings, PE/ELF/Mach-O/APK/archive/Office
                                     parsing, pcap inspection, etc.) replaces
                                     the old general-purpose run_shell. Every
                                     operation is either an in-process Python
                                     library call (no subprocess at all) or a
                                     fixed-argv subprocess with no free-form
                                     command string — there is no shell escape.
                                     Unknown operations are rejected with the
                                     list of valid ones. Runtime package
                                     installation was never available (P0-1)
                                     and still isn't — the analysis image is
                                     expected to ship every tool it needs.
  fetch_url(url, dest)            — SSRF-defended HTTP(S) download: scheme/
                                     DNS/redirect/private-IP validation, size
                                     cap, timeouts. Replaces raw curl/wget.
  clone_repo(url, dest)           — SSRF-defended `git clone --depth 50` with
                                     a post-clone size cap. Replaces raw git.
  cape_submit(...)/cape_status(...)/cape_fetch_report(...)
                                   — typed wrappers around CAPEClient (REST by
                                     default). Replace raw `docker exec cape
                                     ...` submit.py/report shell strings.
  cape_service_check()/cape_vm_start(vm_name)
                                   — narrow, fixed-argv docker exec calls for
                                     service/VM bring-up (no LLM-controlled
                                     shell string beyond a validated VM name).
  read_spec()                     — read the current environment spec
  update_spec(key, value)         — write a finding to the spec
  read_file(path)                 — read a file (capped at MAX_SHELL_OUTPUT chars)
  write_file(path, content)       — write a file
  query_json(file, path, limit)   — read a large JSON file (e.g. a CAPE report)
                                     via a cached, dotted-path query instead of
                                     dumping raw text; returns up to
                                     MAX_QUERY_JSON_OUTPUT chars per call
  finish(summary)                 — signal completion

Reliability features (see AgentLoop.__init__ / run):
  pinned_facts    — key facts (e.g. cape_task_id) folded into the system
                    prompt so they survive context trimming for the whole run
  checkpoint nudge — near max_iterations, the agent is told to stop
                    exploring and write down its best-effort result
  forced finalisation — if max_iterations is hit with no finish() call, a
                    small bounded extra pass forces a best-effort write
                    instead of silently returning nothing
"""

import contextlib
import ipaddress
import hashlib
import json
import logging
import os
import pwd
import re
import resource
import shutil
import signal
import socket
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urljoin

from core.redact import redact as _redact
from core.spec_policy import SpecPermissionError, SpecSchemaError, tool_allowed
from core.run_context import LedgerError
from core.host_ops import ALLOWED_VMS
from core.tool_contracts import tool_contract, validate_call

logger = logging.getLogger("amsa")

# Environment variables passed through to tool subprocesses. Everything
# else — including LLM/API keys and any other secrets in the harness's own
# environment — is stripped so tool processes can't read or leak them
# (closes CTL-08: tool processes previously inherited the full environment).
_SAFE_ENV_PASSTHROUGH = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "SHELL")

# Secret-shaped substrings redacted from commands before they're written to
# the workflow log — logs must not persist plaintext credentials (CTL-08).
# Patterns now live in core/redact.py so WorkflowLog can apply the same
# redaction to everything it persists, not just this module's call site
# (INT-12).

# Tool calls that cause side effects (arbitrary execution / arbitrary file
# write). Malformed/unparseable JSON for these is never recovered via the
# regex fallback parser — it fails closed instead (CTL-09).
# Tools that reach the internet. Disabled during offline analysis so the model
# cannot look a sample up online (evaluation cheating) and a compromised parser
# cannot exfiltrate. Enabled only for Scout on a --url/--repo run, whose task is
# to fetch the sample. See _execute_tool.
_NETWORK_EGRESS_TOOLS = {"fetch_url", "clone_repo", "mb_lookup"}

_HIGH_RISK_TOOLS_NO_FALLBACK = {
    "analyze_sample", "write_file", "fetch_url", "clone_repo",
    "cape_submit", "cape_vm_start",
}

# CTL-01 fix: the general-purpose run_shell tool (subprocess.Popen(shell=True)
# guarded only by a substring denylist) has been removed entirely — a
# denylist is bypassable (write the blocked command to a file and run it,
# base64-decode a payload, etc.) and had no path containment. Every previous
# legitimate use is now served by analyze_sample's fixed operation allowlist
# (see _tool_analyze_sample below) or the other typed tools already listed
# in this module's docstring.

# Directory of prebuilt YARA rule files consulted by the yara_scan operation.
# Fixed constant — never LLM-controlled.
_YARA_RULES_DIR = "/usr/share/yara-rules"

# Static-analysis sidecar: when SANDBOXGEN_ANALYZE_CONTAINER=1 (set by
# run_pipeline.sh), analyze_sample operations run in a --network none, no-socket
# container instead of an in-process fork, so a parser RCE has no network to
# exfiltrate through and no podman socket to reach. The podman command may carry
# --url (podman-remote) so a sidecar is a sibling on the host, same as detonation.
_ANALYZE_IN_CONTAINER = os.environ.get("SANDBOXGEN_ANALYZE_CONTAINER", "") in ("1", "true")
_ANALYZE_IMAGE = os.environ.get("SANDBOXGEN_ANALYZE_IMAGE", "localhost/sandboxgen-analyze:py312")
_ANALYZE_PODMAN = (os.environ.get("SANDBOXGEN_PODMAN")
                   or shutil.which("podman") or "podman").split()
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)  # .../src


def _minimal_env() -> dict:
    env = {k: os.environ[k] for k in _SAFE_ENV_PASSTHROUGH if k in os.environ}
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    return env


# Maximum output from a single shell command returned to the LLM
MAX_SHELL_OUTPUT = 4000

# DATA-01 mitigation: analyze_sample's read-only parsing operations (pefile,
# androguard-style apk inspection, oletools, pdfid, YARA, etc.) run untrusted,
# LLM-selected sample content through parsing libraries that can themselves
# have vulnerabilities — a parser bug there compromises the host before any
# dynamic-analysis sandboxing kicks in. This is NOT the audit's full
# recommendation (a disposable, offline, network-isolated environment) —
# that needs its own dedicated host, a bigger infra decision left open. What
# IS achievable in-process: run each parse in a short-lived forked child
# with hard resource limits and, when the harness runs as root, a dropped
# UID/GID — so a parser crash, fork bomb, or memory-exhaustion bug is
# contained to a disposable child instead of the harness's own long-lived
# process. Set AMSA_SKIP_SAMPLE_SANDBOX=1 to fall back to the old
# direct-in-process behavior if forking misbehaves in a given deployment.
_SANDBOX_CPU_SECONDS   = int(os.environ.get("AMSA_SAMPLE_SANDBOX_CPU_SECONDS", 30))
_SANDBOX_MEM_BYTES     = int(os.environ.get("AMSA_SAMPLE_SANDBOX_MEM_MB", 1024)) * 1024 * 1024
_SANDBOX_FSIZE_BYTES   = int(os.environ.get("AMSA_SAMPLE_SANDBOX_FSIZE_MB", 500)) * 1024 * 1024
_SANDBOX_NOFILE        = 256
_SANDBOX_NPROC         = 64
_SANDBOX_UNPRIV_USER   = os.environ.get("AMSA_SAMPLE_SANDBOX_USER", "nobody")

# Operations that write into the workspace (extraction) need real write
# access and can't run as an unprivileged/unrelated UID — only the
# read-only inspection operations are sandboxed this way.
_SANDBOX_EXEMPT_WRITE_OPS = {"zip_extract", "archive_extract", "apktool_unpack"}


def _drop_privileges_and_limit_resources() -> None:
    """
    Runs inside the forked child only. Order matters: resource limits are
    applied before the privilege drop so an unprivileged child can't raise
    its own limits back up, and the UID drop happens last since it removes
    the ability to make further setuid/setrlimit calls at all.
    """
    resource.setrlimit(resource.RLIMIT_CPU,   (_SANDBOX_CPU_SECONDS, _SANDBOX_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS,    (_SANDBOX_MEM_BYTES, _SANDBOX_MEM_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (_SANDBOX_FSIZE_BYTES, _SANDBOX_FSIZE_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (_SANDBOX_NOFILE, _SANDBOX_NOFILE))
    resource.setrlimit(resource.RLIMIT_CORE,  (0, 0))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (_SANDBOX_NPROC, _SANDBOX_NPROC))
    except (ValueError, OSError):
        pass  # not all kernels/cgroup configs allow this one — best-effort

    if os.geteuid() == 0:
        try:
            target = pwd.getpwnam(_SANDBOX_UNPRIV_USER)
        except KeyError:
            return  # no such user configured — stay root rather than fail closed here
        os.setgroups([])
        os.setgid(target.pw_gid)
        os.setuid(target.pw_uid)

# Maximum output from a structured query_json tool call — larger than
# MAX_SHELL_OUTPUT because results are pre-filtered/structured JSON rather
# than raw command output, so more can be shown per call without blowing
# the context budget as fast.
MAX_QUERY_JSON_OUTPUT = 12000
MAX_SPEC_OUTPUT = 48000


def _result_cap(tool: str) -> int:
    """
    Per-tool truncation limit for formatting a tool result into the
    message sent back to the model. CTL-11 fix: the result-formatting
    loop used to apply MAX_SHELL_OUTPUT to every tool indiscriminately,
    silently re-truncating query_json's already-bounded (and much larger)
    MAX_QUERY_JSON_OUTPUT slice back down to a third of its size.
    """
    if tool == "read_spec":
        return MAX_SPEC_OUTPUT
    if tool == "read_file":
        return MAX_SHELL_OUTPUT + 256  # keep the explicit next-offset marker
    return MAX_QUERY_JSON_OUTPUT if tool == "query_json" else MAX_SHELL_OUTPUT


def _visible_result(tool, result):
    cap = _result_cap(tool)
    if len(result) <= cap:
        return result
    return result[:cap] + (
        f"\n[TRUNCATED: {len(result)} characters total; only {cap} shown. "
        "Use read_spec(path=...) / query_json for a narrower field, "
        "or read_file offset/limit for the next page.]"
    )


# When this many iterations remain before max_iterations, inject a
# checkpoint nudge telling the agent to stop exploring and finalise.
CHECKPOINT_WINDOW = 5

# Extra forced-finalisation iterations granted (beyond max_iterations) if
# the agent still hasn't called finish() when the normal budget runs out.
FINALIZATION_ITERATIONS = 3

# Reasoning models can consume most of a small completion budget before they
# emit the visible tool call. Start above the old 4096-token limit and allow
# bounded growth when the provider reports a truncated completion.
DEFAULT_AGENT_MAX_TOKENS = 8192
MAX_AGENT_MAX_TOKENS = 16384
MAX_CONSECUTIVE_PROTOCOL_ERRORS = 3

# CTL-10 fix: hard wall-clock ceiling per agent stage. max_iterations alone
# doesn't bound wall time — a single tool call (e.g. a CAPE
# wait_for_completion poll, or an LLM backend stuck retrying rate limits)
# can block for a long time without ever incrementing the iteration count.
# Checked once per iteration, so real overrun is bounded by the longest
# single tool/LLM call, not unbounded. Override with
# SANDBOXGEN_MAX_STAGE_WALL_SECONDS for deployments where CAPE analysis
# legitimately runs long.
_DEFAULT_MAX_WALL_SECONDS = int(os.environ.get("SANDBOXGEN_MAX_STAGE_WALL_SECONDS", 2400))

# P0-1 typed-tool limits (fetch_url / clone_repo — replace raw curl/wget/git
# in agent prompts with SSRF-defended, size-capped downloads; audit CTL-05).
_MAX_FETCH_BYTES     = 200 * 1024 * 1024
_MAX_CLONE_BYTES     = 200 * 1024 * 1024
# SG-RES-01: query_json loads the whole file and caches it for the stage.
# CAPE reports of a few hundred MB exist; one of those per stage is enough.
_MAX_QUERY_JSON_FILE_BYTES = 512 * 1024 * 1024
_FETCH_CONNECT_TIMEOUT = 15
_FETCH_READ_TIMEOUT    = 120
_MAX_FETCH_REDIRECTS   = 5


class AgentLoop:
    def __init__(self, llm, system_prompt: str, spec, log,
                 agent_name: str, max_iterations: int = 80,
                 min_iterations: int = 3, pinned_facts: dict = None,
                 cape_client=None, max_wall_seconds: float = None,
                 ctx=None, max_tokens: int = DEFAULT_AGENT_MAX_TOKENS,
                 completion_validator=None,
                 max_consecutive_protocol_errors: int = MAX_CONSECUTIVE_PROTOCOL_ERRORS):
        self.llm            = llm
        self.spec           = spec
        self.log            = log
        self.agent_name     = agent_name
        self.completion_validator = completion_validator
        self._request_number = 0
        self._last_response_metadata = {}
        self._last_parse_diagnostics = {}
        if type(max_consecutive_protocol_errors) is not int or max_consecutive_protocol_errors < 1:
            raise ValueError("max_consecutive_protocol_errors must be a positive integer")
        self.max_consecutive_protocol_errors = max_consecutive_protocol_errors
        # SG-CTL-02: the controller ledger. The loop never writes to it on
        # the model's behalf except through the typed cape_* paths below,
        # and reads it for the RUN FACTS block and for the sample identity.
        self.ctx            = ctx
        self.max_iterations = max_iterations
        self.min_iterations = min_iterations
        self.max_tokens      = max(1, int(max_tokens))
        # This state belongs to the stage, not the shared LLM client. A budget
        # expanded inside a provider retry must survive the next tool round.
        self._retained_max_tokens = min(self.max_tokens, MAX_AGENT_MAX_TOKENS)
        self.max_wall_seconds = (
            max_wall_seconds if max_wall_seconds is not None
            else _DEFAULT_MAX_WALL_SECONDS
        )
        self.messages       = []
        self.finished       = False
        self.finish_summary = None
        self._json_cache    = {}
        # P0-1/P0-2: passed by Executor so cape_submit/cape_status/
        # cape_fetch_report can call the already-hardened CAPEClient
        # (REST by default) instead of the LLM constructing raw
        # `docker exec cape ...` shell strings.
        self.cape_client    = cape_client

        # Pinned facts (e.g. cape_task_id, cape_report_path, sample_sha256)
        # are folded into the system prompt — which is re-sent verbatim on
        # every LLM call — rather than into the message history, so they
        # survive context trimming for the entire run instead of being
        # dropped when old messages are pruned.
        self.pinned_facts = pinned_facts or {}
        if self.pinned_facts:
            pinned_block = "\n".join(f"  {k}: {v}" for k, v in self.pinned_facts.items())
            system_prompt = (
                system_prompt
                + "\n\n═══════════════════════════════════════════════════════════════════\n"
                + "PINNED FACTS — authoritative for this entire run. These values are\n"
                + "fixed by the harness and will NOT change or scroll out of context.\n"
                + "If anything you discover mid-run conflicts with these, TRUST THESE.\n"
                + "═══════════════════════════════════════════════════════════════════\n"
                + pinned_block
            )
        self.system_prompt = system_prompt + tool_contract(agent_name)

    def _system_with_facts(self) -> str:
        """
        The system prompt plus the controller's current RUN FACTS block.

        Rebuilt on every LLM call rather than at construction, because the
        facts change during a stage (a task ID appears after cape_submit)
        and the model must see the ledger's view, not a stale copy.
        """
        system = self.system_prompt
        if self.spec is not None:
            facts = {key: self.spec.get(key) for key in (
                "cape_submission.backend_capabilities", "cape_submission.available_machines")}
            system += "\n\nACTUAL BACKEND AND AVAILABLE MACHINES (controller supplied):\n" + json.dumps(facts, default=str)
        if self.ctx is None:
            return system
        try:
            block = self.ctx.facts().to_prompt_block()
        except Exception as e:      # never let a facts error kill the stage
            block = f"  (run facts unavailable: {e})"
        return (
            system
            + "\n\n═══════════════════════════════════════════════════════════════════\n"
            + "RUN FACTS — recorded by the harness from verified state. These are\n"
            + "the values the controller will act on; update_spec cannot change them.\n"
            + "═══════════════════════════════════════════════════════════════════\n"
            + block
        )

    def _chat(self, max_tokens, phase="normal"):
        max_tokens = min(MAX_AGENT_MAX_TOKENS, max(max_tokens, self._retained_max_tokens))
        self._request_number += 1
        request = self._request_number
        system = self._system_with_facts()
        self.log.trace(self.agent_name, "request", {
            "request": request, "phase": phase, "system": system,
            "messages": self.messages, "max_tokens": max_tokens})
        traced_client = hasattr(self.llm, "trace_callback")
        previous = self.llm.trace_callback if traced_client else None
        if traced_client:
            self.llm.trace_callback = lambda data: self.log.trace(
                self.agent_name, "llm_attempt", {"request": request, **data})
        try:
            response = self.llm.chat(system=system, messages=self.messages, max_tokens=max_tokens)
        except Exception as exc:
            self.log.trace(self.agent_name, "request_error", {
                "request": request, "error_type": type(exc).__name__, "error": str(exc)})
            raise
        finally:
            if traced_client:
                self.llm.trace_callback = previous
        metadata = getattr(self.llm, "last_response_metadata", {})
        self._last_response_metadata = dict(metadata) if isinstance(metadata, dict) else {}
        used_tokens = metadata.get("max_tokens", max_tokens) if isinstance(metadata, dict) else max_tokens
        if isinstance(used_tokens, int) and not isinstance(used_tokens, bool):
            self._retained_max_tokens = min(MAX_AGENT_MAX_TOKENS, max(max_tokens, used_tokens))
        self.log.trace(self.agent_name, "response", {
            "request": request, "text": response,
            "metadata": metadata})
        return response

    def _read_spec(self, call):
        data = json.loads(self.spec.to_json())
        path = call.get("path", "")
        node = self._resolve_json_path(data, path)
        if path and node is None:
            return f"(null / path not found: {path!r})"
        if "offset" in call or "limit" in call:
            offset, limit = call.get("offset", 0), call.get("limit", 100)
            if isinstance(node, dict):
                items = list(node.items())
                node = {"value": dict(items[offset:offset + limit]),
                        "page": {"offset": offset, "total": len(items),
                                 "next_offset": offset + limit if offset + limit < len(items) else None}}
            elif isinstance(node, (list, str)):
                total = len(node)
                node = {"value": node[offset:offset + limit],
                        "page": {"offset": offset, "total": total,
                                 "next_offset": offset + limit if offset + limit < total else None}}
        result = json.dumps(node, indent=2, default=str)
        if len(result) > MAX_SPEC_OUTPUT:
            return json.dumps({"status": "too_large", "path": path,
                               "characters": len(result),
                               "keys": list(node)[:100] if isinstance(node, dict) else None,
                               "instruction": "Select a narrower dotted path with read_spec, or use offset/limit to page this value."})
        return result

    # ------------------------------------------------------------------
    # Context window management
    # ------------------------------------------------------------------

    MAX_CONTEXT_CHARS = 60_000

    def _estimate_chars(self, messages: list) -> int:
        return sum(len(m.get("content", "")) for m in messages)

    def _bound_message_contents(self, messages):
        """Make any remaining per-message cut visible, including recent results."""
        budget = self.MAX_CONTEXT_CHARS // max(1, len(messages))
        marker = "\n[CONTEXT TRUNCATED: re-read needed fields using read_spec(path=...) or query_json.]"
        return [{**m, "content": m["content"] if len(m["content"]) <= budget
                 else m["content"][:max(0, budget - len(marker))] + marker[:budget]}
                for m in messages]

    def _trim_messages(self, messages: list) -> list:
        """
        Keep the first message (initial task) and trim old middle exchanges
        when the conversation grows too large. Always preserves:
          - messages[0]  — the initial task (never removed)
          - last 6 messages — the most recent context
        Middle messages are dropped oldest-first until within budget.
        """
        if self._estimate_chars(messages) <= self.MAX_CONTEXT_CHARS:
            return messages

        if len(messages) <= 7:
            return self._bound_message_contents(messages)

        first  = messages[:1]
        recent = messages[-6:]
        middle = list(messages[1:-6])

        while middle and self._estimate_chars(first + middle + recent) > self.MAX_CONTEXT_CHARS:
            middle.pop(0)

        if not middle:
            trimmed = first + [{"role": "user",
                                "content": "[Earlier conversation trimmed to fit context window]"}] + recent
        else:
            trimmed = first + middle + recent

        if self._estimate_chars(trimmed) > self.MAX_CONTEXT_CHARS:
            trimmed = self._bound_message_contents(trimmed)
        self.log.info(self.agent_name,
                      f"Context trimmed: {len(messages)} -> {len(trimmed)} messages "
                      f"({self._estimate_chars(trimmed)} chars)")
        return trimmed

    # ------------------------------------------------------------------

    def run(self, initial_message: str) -> dict:
        self.messages = [{"role": "user", "content": initial_message}]
        consecutive_protocol_errors = 0
        termination_reason = "iteration_budget_exhausted"
        deadline = time.monotonic() + self.max_wall_seconds
        # Keep provider retry growth, but don't assume every protocol error
        # means truncation: ordinary malformed output needs format repair.
        cur_max_tokens = min(self.max_tokens, MAX_AGENT_MAX_TOKENS)

        for iteration in range(1, self.max_iterations + 1):
            if time.monotonic() >= deadline:
                termination_reason = "wall_time_exhausted"
                self.log.warning(
                    self.agent_name,
                    f"Hit wall-time budget ({self.max_wall_seconds}s) at "
                    f"iteration {iteration}/{self.max_iterations} — forcing finalisation."
                )
                self._force_finalize(cur_max_tokens, reason=termination_reason)
                break

            self.log.info(self.agent_name,
                          f"Iteration {iteration}/{self.max_iterations}")

            self.messages = self._trim_messages(self.messages)

            remaining = self.max_iterations - iteration
            if 0 < remaining <= CHECKPOINT_WINDOW:
                self.messages.append({
                    "role": "user",
                    "content": (
                        f"CHECKPOINT: only {remaining} iteration(s) remain before this "
                        f"stage is aborted. Stop exploring/re-verifying now. On this turn, "
                        f"write down the best-effort result you already have (via update_spec "
                        f"and/or write_file) and call finish() with a summary. A partial, "
                        f"honestly-caveated result beats no result."
                    )
                })

            response = self._chat(cur_max_tokens)

            tool_calls = self._parse_tool_calls(response)
            if not tool_calls or not self._last_parse_diagnostics.get("valid_call_count"):
                consecutive_protocol_errors += 1
                cur_max_tokens = self._recover_protocol_error(
                    response, cur_max_tokens, consecutive_protocol_errors)
                if consecutive_protocol_errors >= self.max_consecutive_protocol_errors:
                    termination_reason = "protocol_stalled"
                    self._force_finalize(cur_max_tokens, reason=termination_reason)
                    break
                continue

            consecutive_protocol_errors = 0

            results = []
            for call in tool_calls:
                if not isinstance(call, dict):
                    # A model can emit `<tool_call>["x"]</tool_call>`; the old
                    # code called .get() on it and the whole stage died.
                    results.append({"tool": "?", "result":
                                    "ERROR: tool call must be a JSON object"})
                    continue
                if call.get("tool") == "finish" and iteration < self.min_iterations:
                    self.log.warning(
                        self.agent_name,
                        f"Blocked early finish() at iteration {iteration} "
                        f"(min_iterations={self.min_iterations}). "
                        f"Agent must complete more steps first."
                    )
                    results.append({
                        "tool":   "finish",
                        "result": (
                            f"ERROR: finish() called too early (iteration {iteration}). "
                            f"You must complete at least {self.min_iterations} iterations "
                            f"of actual work before finishing. Continue with the next "
                            f"mandatory step in your workflow."
                        )
                    })
                    continue

                result = self._execute_tool(call)
                results.append(result)
                if self.finished:
                    break

            result_text = "\n".join([
                f"[{r['tool']}] → {_visible_result(r['tool'], r['result'])}"
                for r in results
            ])
            self.log.trace(self.agent_name, "feedback", {
                "request": self._request_number, "results": results, "text": result_text})

            self.messages.append({"role": "assistant", "content": response})
            self.messages.append({"role": "user",      "content": result_text})

            if self.finished:
                self.log.info(self.agent_name,
                              f"Agent complete after {iteration} iterations.")
                break

        else:
            self.log.warning(self.agent_name,
                             f"Hit max_iterations={self.max_iterations}")
            self._force_finalize(cur_max_tokens)

        outcome = {
            "finished":   self.finished,
            "summary":    self.finish_summary,
            "iterations": self._request_number,
            "termination_reason": "completed" if self.finished else termination_reason,
        }
        self.log.trace(self.agent_name, "stage_outcome", outcome)
        return outcome

    # ------------------------------------------------------------------

    def _recover_protocol_error(self, response, max_tokens, consecutive, phase="normal"):
        """Explain the actual failure and bound growth to proven truncation."""
        diagnostics = self._last_parse_diagnostics
        finish_reason = self._last_response_metadata.get("finish_reason")
        previous_budget = min(MAX_AGENT_MAX_TOKENS, max(max_tokens, self._retained_max_tokens))
        max_tokens = previous_budget
        if finish_reason in {"length", "max_tokens"}:
            max_tokens = min(previous_budget * 2, MAX_AGENT_MAX_TOKENS)
        self._retained_max_tokens = max_tokens
        self.log.trace(self.agent_name, "protocol_recovery", {
            "request": self._request_number, "phase": phase,
            "consecutive_errors": consecutive,
            "normal_limit": self.max_consecutive_protocol_errors,
            "finish_reason": finish_reason, "diagnostics": diagnostics,
            "previous_max_tokens": previous_budget, "next_max_tokens": max_tokens})
        self.log.warning(self.agent_name,
                         f"Tool protocol error: {diagnostics.get('status')} "
                         f"(consecutive={consecutive}, phase={phase}, max_tokens={max_tokens})")
        if response:
            self.messages.append({"role": "assistant", "content": response})
        details = "; ".join(diagnostics.get("errors", [])[:3])
        advice = {
            "empty_response": "Your visible response was empty.",
            "no_tool_call": "Your response contained no JSON tool call.",
            "malformed_json": "Your tool-call JSON was malformed or incomplete. Include the opening and closing braces and properly quoted keys.",
            "invalid_tool_schema": "Your JSON did not match the tool contract. " + details,
        }.get(diagnostics.get("status"), details)
        if finish_reason in {"length", "max_tokens"}:
            advice += " The provider reported output truncation; emit one short call without preceding analysis."
        elif finish_reason:
            advice += f" The provider ended with finish_reason={finish_reason}; no truncation was reported."
        self.messages.append({"role": "user", "content": (
            f"TOOL PROTOCOL REPAIR: {advice} No tool was executed from this response. "
            "Emit one complete JSON object inside each <tool_call>...</tool_call> block, "
            "using an allowed tool and its required flat fields from the AUTHORITATIVE TOOL CONTRACT. "
            "Do not use XML argument tags or nested arguments/parameters. "
            "Emit the next required action directly. Before finish, save and validate all required outputs; "
            "finish alone does not create a report or waive completion requirements."
        )})
        return max_tokens

    def _force_finalize(self, max_tokens=None, reason="iteration_budget_exhausted") -> None:
        """
        Called when a stage reaches its budget or stalls on protocol errors
        without completing. Rather than silently returning nothing
        (which previously produced e.g. "Classification: unknown" with no
        analysis_report.json ever written), spend a small, separate budget
        forcing the agent to write down whatever best-effort result it has
        instead of continuing to explore.
        """
        self.log.warning(
            self.agent_name,
            f"Forcing finalisation after {reason} ({FINALIZATION_ITERATIONS} extra iterations, "
            f"exploration tools disabled)."
        )

        self.messages = self._trim_messages(self.messages)
        self.messages.append({
            "role": "user",
            "content": (
                f"Normal execution stopped ({reason}) without completing this stage. "
                "This is now a forced finalisation pass: you may still call "
                "read_spec / update_spec / append_spec / write_file / finish, but do NOT run further "
                "exploratory commands — use only what you have already learned in this "
                "conversation and whatever is already in the spec. Write the best-effort "
                "final result NOW (mark it explicitly as partial/best-effort if it is "
                "incomplete, and note what could not be confirmed), then call finish() "
                "with a summary. Record any blocker honestly. All required outputs and "
                "completion checks still apply; finish alone cannot create a missing report."
            )
        })

        allowed_tools = {"update_spec", "append_spec", "write_file",
                          "read_spec", "log_decision", "log_observation", "finish"}

        fin_max_tokens = min(max(max_tokens or self.max_tokens, DEFAULT_AGENT_MAX_TOKENS),
                             MAX_AGENT_MAX_TOKENS)
        consecutive_protocol_errors = 0
        for extra_iter in range(1, FINALIZATION_ITERATIONS + 1):
            self.messages = self._trim_messages(self.messages)
            self.log.info(self.agent_name,
                          f"Finalisation iteration {extra_iter}/{FINALIZATION_ITERATIONS}")

            response = self._chat(fin_max_tokens, phase="finalisation")
            tool_calls = self._parse_tool_calls(response)
            if not tool_calls or not self._last_parse_diagnostics.get("valid_call_count"):
                consecutive_protocol_errors += 1
                fin_max_tokens = self._recover_protocol_error(
                    response, fin_max_tokens, consecutive_protocol_errors, phase="finalisation")
                continue
            consecutive_protocol_errors = 0
            self.messages.append({"role": "assistant", "content": response})

            results = []
            for call in tool_calls:
                if not isinstance(call, dict):
                    results.append({"tool": "?", "result":
                                    "ERROR: tool call must be a JSON object"})
                    continue
                tool = call.get("tool", "")
                if not isinstance(tool, str) or tool not in allowed_tools:
                    results.append({
                        "tool": tool,
                        "result": f"ERROR: '{tool}' is disabled during forced finalisation. "
                                   f"Use update_spec/append_spec/write_file/finish only."
                    })
                    continue
                result = self._execute_tool(call)
                results.append(result)
                if self.finished:
                    break

            result_text = "\n".join([
                f"[{r['tool']}] → {_visible_result(r['tool'], r['result'])}" for r in results
            ])
            self.log.trace(self.agent_name, "feedback", {
                "request": self._request_number, "results": results, "text": result_text})
            self.messages.append({"role": "user", "content": result_text})

            if self.finished:
                self.log.info(self.agent_name,
                              f"Finalised during forced pass, iteration {extra_iter}.")
                return

        if not self.finished:
            self.log.warning(self.agent_name,
                             "Forced finalisation exhausted without finish() call.")

    # ------------------------------------------------------------------
    # Tool call parsing — updated to handle multiline JSON
    # ------------------------------------------------------------------

    def _parse_tool_calls(self, response: str) -> list:
        """
        Parse tool calls from LLM response.
        The agent is instructed to output tool calls as:

        <tool_call>
        {"tool": "analyze_sample", "operation": "identify", "path": "..."}
        </tool_call>

        Handles both single-line and multiline JSON strings.
        Multiple tool calls per response are supported.
        """
        calls = []
        errors = []
        valid_call_count = 0
        raw_objects, incomplete = self._scan_json_objects(response or "")
        malformed = incomplete
        for raw in raw_objects:
            obj = None
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                # heredoc-style values with literal newlines inside strings
                try:
                    obj = json.loads(self._normalize_json_strings(raw))
                except json.JSONDecodeError:
                    pass
            if isinstance(obj, dict) and "tool" in obj:
                calls.append(obj)
                error = validate_call(obj)
                if not error and not tool_allowed(self.agent_name, obj["tool"]):
                    error = f"ERROR: tool '{obj['tool']}' is not allowed for {self.agent_name}."
                if error:
                    errors.append(error)
                else:
                    valid_call_count += 1
            elif isinstance(obj, dict):
                errors.append("ERROR: missing top-level 'tool' field; use flat named fields.")
            elif obj is None:
                malformed = True
                self.log.warning(self.agent_name,
                                 f"Failed to parse tool call JSON: {raw[:100]}")
            else:
                errors.append("ERROR: each tool call must be a JSON object, not an array or scalar.")
        if not raw_objects and response and "<tool_call>" in response:
            malformed = True
        if valid_call_count:
            status = "parsed"
        elif not response or not response.strip():
            status = "empty_response"
        elif errors:
            status = "invalid_tool_schema"
        elif malformed or "<tool_call>" in response:
            status = "malformed_json"
        else:
            status = "no_tool_call"
        self._last_parse_diagnostics = {
            "status": status, "errors": errors, "valid_call_count": valid_call_count,
            "malformed_json": malformed, "incomplete_json": incomplete}
        self.log.trace(self.agent_name, "parsed_calls", {
            "request": self._request_number, "calls": calls,
            "empty": not bool(calls), "diagnostics": self._last_parse_diagnostics})
        return calls

    @staticmethod
    def _extract_json_objects(text: str) -> list:
        return [raw for raw in AgentLoop._scan_json_objects(text)[0] if raw.startswith("{")]

    @staticmethod
    def _scan_json_objects(text: str) -> tuple:
        """
        Extract complete objects without interpreting prose as JSON strings.

        An opening tool tag outside a JSON string starts a fresh boundary, so
        an unmatched prose brace cannot swallow the following call. Inside an
        object, strings and nested objects remain opaque: tool-looking text in
        write_file content is never promoted into a separate action. Adjacent
        open tags without closing tags, and tagless JSON, remain supported.
        """
        objs = []
        incomplete = False
        depth = 0
        start = -1
        in_tool_block = False
        in_str = False
        esc = False
        for i, ch in enumerate(text):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == "<" and text.startswith("<tool_call>", i):
                # Resynchronise prose only. Once a tagged JSON container has
                # started, an inner tag cannot rescue a malformed outer call.
                if depth == 0 or not in_tool_block:
                    incomplete = incomplete or depth > 0
                    depth, start = 0, -1
                    in_tool_block = True
            elif ch == '"' and depth > 0:
                in_str = True
            elif ch in "{[":
                if depth == 0:
                    start = i
                depth += 1
            elif ch in "}]":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start >= 0:
                        objs.append(text[start:i + 1])
                        start = -1
                        in_tool_block = False
        return objs, incomplete or depth > 0

    def _normalize_json_strings(self, raw: str) -> str:
        """
        Walk the raw JSON character by character and replace literal
        newlines and tabs that appear inside string values with their
        escape sequences. This makes heredoc-style command strings
        parseable without altering the JSON structure.
        """
        result      = []
        in_string   = False
        escape_next = False

        for char in raw:
            if escape_next:
                result.append(char)
                escape_next = False
                continue

            if char == '\\':
                escape_next = True
                result.append(char)
                continue

            if char == '"':
                in_string = not in_string
                result.append(char)
                continue

            if in_string and char == '\n':
                result.append('\\n')
                continue

            if in_string and char == '\t':
                result.append('\\t')
                continue

            result.append(char)

        return ''.join(result)

    def _extract_fields_fallback(self, raw: str) -> dict:
        """
        Last-resort regex extraction when JSON is too malformed to parse
        even after normalization. Extracts tool name and key fields only.
        Raises ValueError if tool name cannot be found.
        """
        result = {}

        tool_match = re.search(r'"tool"\s*:\s*"([^"]+)"', raw)
        if not tool_match:
            raise ValueError("Could not extract tool name")
        tool = tool_match.group(1)
        if tool in _HIGH_RISK_TOOLS_NO_FALLBACK:
            # Fail closed: malformed/injected JSON must never be recovered
            # into an executable analyze_sample/write_file call (CTL-09).
            raise ValueError(
                f"refusing regex-fallback recovery for high-risk tool '{tool}' — "
                f"malformed JSON for side-effecting tools fails closed"
            )
        result['tool'] = tool

        # Command: capture everything between "command": " and the next
        # unescaped quote, allowing for embedded newlines
        cmd_match = re.search(
            r'"command"\s*:\s*"(.*?)(?<!\\)"', raw, re.DOTALL
        )
        if cmd_match:
            result['command'] = cmd_match.group(1).replace('\\n', '\n')

        # Spec key/value for update_spec calls
        key_match = re.search(r'"key"\s*:\s*"([^"]+)"', raw)
        val_match = re.search(r'"value"\s*:\s*"([^"]+)"', raw)
        if key_match:
            result['key'] = key_match.group(1)
        if val_match:
            result['value'] = val_match.group(1)

        # Summary for finish() calls
        summary_match = re.search(r'"summary"\s*:\s*"([^"]+)"', raw)
        if summary_match:
            result['summary'] = summary_match.group(1)

        return result

    # ------------------------------------------------------------------

    def _confine_to_workspace(self, path: str) -> Path:
        """
        Resolve `path` against the per-run workspace and refuse anything
        that escapes it — absolute paths outside the workspace, '..'
        traversal, or a symlink whose real target lands outside (resolve()
        dereferences symlinks before the containment check, so a symlink
        pointing outside the workspace is caught here too). Closes CTL-02.
        """
        workspace = self.spec.workspace.resolve()
        candidate = Path(path)
        resolved  = (candidate if candidate.is_absolute() else workspace / candidate).resolve()
        if not resolved.is_relative_to(workspace):
            raise ValueError(
                f"path '{path}' resolves outside the run workspace ({workspace}) — refused"
            )
        return resolved

    def _confine_analysis_path(self, path: str) -> Path:
        """
        Like _confine_to_workspace, but additionally allows READ-ONLY access
        to the single originally-supplied sample file when it lives outside
        the workspace (spec.sample.path — resolved to an absolute, validated
        path by the orchestrator before any agent runs, per INT-10). This
        exception is single-file and read-only: any operation with a
        destination/write argument (extraction, unpacking) must validate
        that argument through _confine_to_workspace directly, never through
        this method — that is the one place a bug here would reopen a real
        arbitrary-write hole.
        """
        try:
            return self._confine_to_workspace(path)
        except ValueError:
            # SG-DATA-02: when a ledger is present the exception is granted
            # against the identity the controller pinned — by (dev, inode),
            # not by comparing two path strings — so a rewritten spec field
            # cannot widen it. The spec lookup remains only for loops built
            # without a ledger (tests).
            try:
                candidate = Path(path).resolve()
            except OSError:
                raise ValueError(f"path '{path}' cannot be resolved — refused")
            if self.ctx is not None and self.ctx.has_sample:
                if self.ctx.sample.matches(candidate):
                    return candidate
                raise
            sample_path = self.spec.get("sample.path")
            if sample_path:
                try:
                    if candidate == Path(sample_path).resolve():
                        return candidate
                except OSError:
                    pass
            raise

    def _execute_tool(self, call: dict) -> dict:
        error = validate_call(call)
        name = call.get("tool") if isinstance(call, dict) else None
        result = {"tool": name if isinstance(name, str) else "?", "result": error} if error else self._dispatch_tool(call)
        self.log.trace(self.agent_name, "tool_result", {
            "request": self._request_number, "call": call, "result": result,
            "delivered_result": _visible_result(result["tool"], result["result"])})
        return result

    def _dispatch_tool(self, call: dict) -> dict:
        tool   = call.get("tool", "")
        result = ""

        # SG-CTL-03: the role decides which tools exist, not the prompt. A
        # refusal is returned as a tool result so the model can adapt rather
        # than silently getting an "unknown tool" for something it was told
        # about in another role's prompt.
        if not tool_allowed(self.agent_name, tool):
            self.log.warning(self.agent_name,
                             f"Tool {tool!r} is not available to role {self.agent_name!r}")
            return {"tool": tool,
                    "result": f"ERROR: tool '{tool}' is not available to the "
                              f"{self.agent_name} role"}

        # Evaluation integrity + containment: no agent reaches the internet
        # during analysis. It could otherwise look the sample's hash up online
        # and copy the answer (cheating), or a compromised parser could
        # exfiltrate. The harness's own LLM call is the only egress. Egress
        # tools work only for Scout on a --url/--repo run whose task is to fetch
        # the sample; for a local --binary benchmark sample they are refused.
        if tool in _NETWORK_EGRESS_TOOLS and not (
                self.agent_name == "Scout"
                and self.ctx is not None
                and getattr(self.ctx, "allow_sample_download", False)):
            self.log.warning(self.agent_name,
                             f"Network tool {tool!r} refused (offline analysis)")
            return {"tool": tool,
                    "result": (f"ERROR: '{tool}' is disabled — this run performs "
                               f"OFFLINE analysis with no internet access, to keep "
                               f"the evaluation honest and the sample contained. "
                               f"Analyse only what is already on disk.")}

        try:
            if tool == "analyze_sample":
                result = self._tool_analyze_sample(call)
                options_str = _redact(str(call.get("options") or ""))
                self.log.tool_call(self.agent_name, "analyze_sample",
                                   f"{call.get('operation','')} {call.get('path','')} {options_str}")

            elif tool == "read_spec":
                result = self._read_spec(call)
                self.log.tool_call(self.agent_name, "read_spec", "read environment spec")

            elif tool == "update_spec":
                key   = call.get("key", "")
                value = call.get("value")
                # SG-CTL-02: this is the door the audit traced from a model
                # response to `sample.path` and to CAPE task IDs. The write is
                # attributed to the calling role and authorised by
                # `spec_policy`, so a refusal is reported back to the model as
                # a tool error rather than silently succeeding.
                try:
                    self.spec.set(key, value, actor=self.agent_name)
                    result = f"OK — spec updated: {key}"
                except (SpecPermissionError, SpecSchemaError) as e:
                    result = f"REFUSED — {e}"
                self.log.tool_call(self.agent_name, "update_spec",
                                   f"{key} = {str(value)[:80]} → {result[:40]}")

            elif tool == "append_spec":
                key   = call.get("key", "")
                value = call.get("value")
                try:
                    self.spec.append(key, value, actor=self.agent_name)
                    result = f"OK — appended to spec: {key}"
                except (SpecPermissionError, SpecSchemaError) as e:
                    result = f"REFUSED — {e}"
                self.log.tool_call(self.agent_name, "append_spec",
                                   f"{key} += {str(value)[:80]} → {result[:40]}")

            elif tool == "read_file":
                path = call.get("path", "")
                try:
                    resolved = self._confine_to_workspace(path)
                    content  = resolved.read_text(errors="replace")
                    offset = call.get("offset", 0)
                    limit = min(call.get("limit", MAX_SHELL_OUTPUT), MAX_SHELL_OUTPUT)
                    result = content[offset:offset + limit]
                    if offset + limit < len(content):
                        result += f"\n[TRUNCATED: next read_file offset={offset + limit}; total={len(content)} characters]"
                    self.log.tool_call(self.agent_name, "read_file", path)
                except Exception as e:
                    result = f"ERROR reading {path}: {e}"
                    self.log.error(self.agent_name,
                                   f"Tool error (read_file): {_redact(result)[:1000]}")

            elif tool == "write_file":
                path    = call.get("path", "")
                content = call.get("content", "")
                try:
                    resolved = self._confine_to_workspace(path)
                    if resolved.name == "agent_trace.jsonl":
                        raise ValueError("agent_trace.jsonl is controller-owned and cannot be overwritten")
                    if resolved.exists() and not resolved.is_file():
                        raise ValueError(
                            f"refusing to write over non-regular-file target: {resolved}"
                        )
                    resolved.parent.mkdir(parents=True, exist_ok=True)
                    fd = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w") as f:
                        f.write(content)
                    result = f"OK — written {len(content)} bytes to {resolved}"
                    self.log.tool_call(self.agent_name, "write_file",
                                       f"{path} ({len(content)} bytes)")
                except Exception as e:
                    result = f"ERROR writing {path}: {e}"
                    self.log.error(self.agent_name,
                                   f"Tool error (write_file): {_redact(result)[:1000]}")

            elif tool == "fetch_url":
                result = self._tool_fetch_url(call.get("url", ""), call.get("dest", ""))
                self.log.tool_call(self.agent_name, "fetch_url", call.get("url", ""))

            elif tool == "clone_repo":
                result = self._tool_clone_repo(call.get("url", ""), call.get("dest", ""))
                self.log.tool_call(self.agent_name, "clone_repo", call.get("url", ""))

            elif tool == "mb_lookup":
                result = self._tool_mb_lookup(call.get("sha256", ""), call.get("dest", ""))
                self.log.tool_call(self.agent_name, "mb_lookup", call.get("sha256", ""))

            elif tool == "cape_submit":
                result = self._tool_cape_submit(call)
                self.log.tool_call(self.agent_name, "cape_submit", call.get("sample_path", ""))

            elif tool == "cape_status":
                result = self._tool_cape_status(call)
                self.log.tool_call(self.agent_name, "cape_status", str(call.get("task_id", "")))

            elif tool == "cape_fetch_report":
                result = self._tool_cape_fetch_report(call)
                self.log.tool_call(self.agent_name, "cape_fetch_report", str(call.get("task_id", "")))

            elif tool == "cape_service_check":
                result = self._tool_cape_service_check()
                self.log.tool_call(self.agent_name, "cape_service_check", "")

            elif tool == "cape_vm_start":
                result = self._tool_cape_vm_start(call.get("vm_name", ""))
                self.log.tool_call(self.agent_name, "cape_vm_start", call.get("vm_name", ""))

            elif tool == "query_json":
                result = self._query_json(
                    call.get("file", ""),
                    call.get("path", ""),
                    call.get("limit", 50),
                )
                self.log.tool_call(self.agent_name, "query_json",
                                   f"{call.get('file','')} @ {call.get('path','') or '(root)'}")

            elif tool == "log_decision":
                message   = call.get("message", "")
                reasoning = call.get("reasoning", "")
                self.log.decision(self.agent_name, message, reasoning)
                result = "OK — decision logged"

            elif tool == "log_observation":
                message = call.get("message", "")
                self.log.observation(self.agent_name, message)
                result = "OK — observation logged"

            elif tool == "finish":
                if self.completion_validator is not None:
                    problems = self.completion_validator()
                    if problems:
                        return {"tool": tool, "result": "ERROR: required outputs are incomplete: " + "; ".join(problems)}
                summary             = call.get("summary", "")
                self.finished       = True
                self.finish_summary = summary
                result              = f"OK — agent finished: {summary}"
                self.log.info(self.agent_name, f"Finished: {summary}")

            else:
                result = f"ERROR: Unknown tool '{tool}'"
                self.log.warning(self.agent_name, f"Unknown tool called: {tool}")

        except Exception as e:
            result = f"ERROR executing {tool}: {e}"
            self.log.error(self.agent_name, f"Tool error ({tool}): {e}")

        return {"tool": tool, "result": result}

    # ------------------------------------------------------------------

    def _query_json(self, file_path: str, json_path: str, limit) -> str:
        """
        Load a (possibly large) JSON file once, cache it in memory for the
        rest of this agent run, and return a bounded slice addressed by a
        simple dotted path (e.g. "signatures", "behavior.summary.file_written",
        "network.hosts", "behavior.processes[0].calls"). Returns a much
        larger slice than analyze_sample/read_file allow (MAX_QUERY_JSON_OUTPUT
        vs MAX_SHELL_OUTPUT) because the output is pre-filtered structured
        JSON rather than raw, unbounded command output — this is the
        primary mechanism for inspecting large CAPE reports without needing
        dozens of narrow shell round-trips.
        """
        try:
            limit = max(1, min(int(limit), 200))
        except (TypeError, ValueError):
            limit = 50

        try:
            # SG-DATA-01: this tool used to open any path the harness could
            # read, which made it a bypass of read_file's containment and a
            # way to pull config files (with keys) into the model context.
            # Reports the harness writes all live in the workspace.
            resolved = self._confine_to_workspace(file_path)
            key = str(resolved)
            info = resolved.stat()
            version = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            cached = self._json_cache.get(key)
            if cached is None or cached[0] != version:
                if info.st_size > _MAX_QUERY_JSON_FILE_BYTES:
                    return (f"ERROR: {file_path} is {info.st_size} bytes, "
                            f"above the {_MAX_QUERY_JSON_FILE_BYTES} byte cap for query_json")
                self._json_cache[key] = (version, json.loads(resolved.read_text()))
            data = self._json_cache[key][1]
        except Exception as e:
            return f"ERROR loading {file_path}: {e}"

        try:
            node = self._resolve_json_path(data, json_path)
        except Exception as e:
            return f"ERROR resolving path '{json_path}': {e}"

        if node is None:
            return f"(null / path not found: '{json_path}')"

        if isinstance(node, list):
            preview = node[:limit]
            header  = f"[list, length={len(node)}, showing first {len(preview)} " \
                      f"(increase 'limit' or index with path[N] for more)]\n"
            body    = json.dumps(preview, default=str)
        elif isinstance(node, dict):
            keys = list(node.keys())
            preview = {k: node[k] for k in keys[:limit]}
            header  = f"[dict, {len(keys)} keys, showing first {len(preview)}]\n"
            body    = json.dumps(preview, default=str)
        else:
            header = ""
            body   = json.dumps(node, default=str)

        out = header + body
        if len(out) > MAX_QUERY_JSON_OUTPUT:
            out = out[:MAX_QUERY_JSON_OUTPUT] + \
                  f"\n... [truncated at {MAX_QUERY_JSON_OUTPUT} chars — use a more " \
                  f"specific path or smaller limit]"
        return out

    @staticmethod
    def _resolve_json_path(obj, path: str):
        """Resolve a dotted path with optional [N] indices, e.g. 'a.b[0].c'."""
        if not path:
            return obj
        cur = obj
        for part in path.split('.'):
            m = re.match(r'^([^\[\]]*)((?:\[\d+\])*)$', part)
            if not m:
                return None
            key, idx_part = m.group(1), m.group(2)
            if key:
                if isinstance(cur, dict):
                    cur = cur.get(key)
                else:
                    return None
            for idx in re.findall(r'\[(\d+)\]', idx_part):
                if isinstance(cur, list):
                    i = int(idx)
                    cur = cur[i] if 0 <= i < len(cur) else None
                else:
                    return None
            if cur is None:
                return None
        return cur

    # ------------------------------------------------------------------
    # P0-1 typed tools — replace the specific catastrophic capabilities
    # (network egress, Docker/CAPE control, package installs) that the old
    # unrestricted run_shell used to grant, per audit CTL-01/CTL-04/CTL-05/CTL-06.
    # ------------------------------------------------------------------

    @staticmethod
    @contextlib.contextmanager
    def _pinned_resolution(hostname: str, pinned_ip: str):
        """
        CTL-05 fix: closes the DNS-rebinding TOCTOU between
        _validate_fetch_host() validating a resolved address and the actual
        HTTP connection re-resolving the same hostname independently. Pins
        socket.getaddrinfo() for exactly `hostname` to the already-validated
        `pinned_ip` for the duration of the request, so requests/urllib3
        connect to the address that was actually checked — a DNS answer
        that differs between the two lookups can no longer bypass the
        private/loopback/metadata check. Only the connection target
        changes; the Host header and TLS SNI still use the real hostname,
        so certificate validation is unaffected.

        Process-wide monkeypatch, scoped to one tool call — safe here
        because AgentLoop executes tool calls sequentially, not
        concurrently, but not safe to reuse in a multithreaded context.
        """
        orig_getaddrinfo = socket.getaddrinfo

        def _patched(host, port, *args, **kwargs):
            if host == hostname:
                host = pinned_ip
            return orig_getaddrinfo(host, port, *args, **kwargs)

        socket.getaddrinfo = _patched
        try:
            yield
        finally:
            socket.getaddrinfo = orig_getaddrinfo

    @staticmethod
    def _validate_fetch_host(url: str) -> str:
        """
        SSRF defense (audit CTL-05/DATA-03): only http/https, and every
        resolved address for the host must be a public, routable unicast
        address — reject loopback/private/link-local/multicast/reserved/
        unspecified, and explicitly the cloud-metadata address. Raises
        ValueError with a human-readable reason on any violation.
        """
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"scheme '{parsed.scheme or url}' not permitted — only http/https")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"no hostname in URL '{url}'")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise ValueError(f"DNS resolution failed for '{hostname}': {e}")
        if not infos:
            raise ValueError(f"DNS resolution returned no addresses for '{hostname}'")
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local or
                    ip.is_multicast or ip.is_reserved or ip.is_unspecified or
                    str(ip) == "169.254.169.254"):
                raise ValueError(
                    f"host '{hostname}' resolves to {ip}, a private/loopback/"
                    f"link-local/reserved/metadata address — refused"
                )
        return str(infos[0][4][0])

    def _tool_fetch_url(self, url: str, dest: str) -> str:
        if not url or not dest:
            return "ERROR: fetch_url requires both 'url' and 'dest'"
        try:
            resolved = self._confine_to_workspace(dest)
        except Exception as e:
            return f"ERROR: {e}"

        try:
            import requests
        except ImportError:
            return "ERROR: requests library not available"

        current_url = url
        for _hop in range(_MAX_FETCH_REDIRECTS + 1):
            try:
                pinned_ip = self._validate_fetch_host(current_url)
            except ValueError as e:
                return f"ERROR: {e}"
            hostname = urlsplit(current_url).hostname

            try:
                with self._pinned_resolution(hostname, pinned_ip):
                    resp = requests.get(
                        current_url, stream=True, allow_redirects=False,
                        timeout=(_FETCH_CONNECT_TIMEOUT, _FETCH_READ_TIMEOUT),
                        headers={"User-Agent": "SandboxGEN-Scout/1.0"},
                    )
            except requests.RequestException as e:
                return f"ERROR: request to {current_url} failed: {e}"

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    return f"ERROR: redirect (HTTP {resp.status_code}) with no Location header"
                current_url = urljoin(current_url, location)
                continue

            if resp.status_code != 200:
                snippet = ""
                try:
                    snippet = next(resp.iter_content(200, decode_unicode=False)).decode(errors="replace")
                except Exception:
                    pass
                resp.close()
                return f"ERROR: HTTP {resp.status_code} fetching {current_url}: {snippet[:200]}"

            total = 0
            try:
                resolved.parent.mkdir(parents=True, exist_ok=True)
                with open(resolved, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > _MAX_FETCH_BYTES:
                            resolved.unlink(missing_ok=True)
                            return (f"ERROR: download exceeded "
                                    f"{_MAX_FETCH_BYTES} byte cap — aborted")
                        f.write(chunk)
            finally:
                resp.close()
            return f"OK — fetched {total} bytes from {current_url} -> {resolved}"

        return f"ERROR: exceeded {_MAX_FETCH_REDIRECTS} redirects fetching {url}"

    def _tool_clone_repo(self, url: str, dest: str) -> str:
        if not url or not dest:
            return "ERROR: clone_repo requires both 'url' and 'dest'"
        try:
            resolved = self._confine_to_workspace(dest)
        except Exception as e:
            return f"ERROR: {e}"

        # NOTE (CTL-05 residual gap): unlike _tool_fetch_url, DNS pinning
        # can't be applied here — `git clone` resolves the hostname itself
        # inside a separate subprocess, outside Python's socket module, so
        # _pinned_resolution() has no effect on it. The validation below is
        # placed immediately before the subprocess call (no network activity
        # in between) to keep the TOCTOU window as small as possible, but a
        # second DNS answer for the same hostname at git's own resolution
        # time cannot be ruled out from inside this process. Fully closing
        # this requires routing clone_repo through an egress proxy that
        # pins/filters DNS for the whole container (audit P0 recommendation
        # #9), not a code change here.
        try:
            self._validate_fetch_host(url)
        except ValueError as e:
            return f"ERROR: {e}"

        resolved.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth", "50", "--", url, str(resolved)]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                env=_minimal_env(),
            )
        except subprocess.TimeoutExpired:
            return "ERROR: git clone timed out after 120s"
        except FileNotFoundError:
            return "ERROR: git binary not found on this image"
        if proc.returncode != 0:
            return f"ERROR: git clone failed: {(proc.stderr or proc.stdout)[:1000]}"

        try:
            size = sum(f.stat().st_size for f in resolved.rglob("*") if f.is_file())
        except Exception:
            size = -1
        if size > _MAX_CLONE_BYTES:
            shutil.rmtree(resolved, ignore_errors=True)
            return f"ERROR: cloned repo was {size} bytes (> {_MAX_CLONE_BYTES} cap) — removed"
        return f"OK — cloned {url} -> {resolved} ({size} bytes)"

    def _tool_mb_lookup(self, sha256: str, dest: str) -> str:
        """
        MalwareBazaar's get_file API needs a POST with an Auth-Key header,
        which fetch_url (GET-only) can't express — and the prompt's former
        `<YOUR_MALWAREBAZAAR_API_KEY>` placeholder was never actually
        reachable anyway (tool subprocesses get a stripped env, see
        _minimal_env / CTL-08). This reads the key from the harness's own
        (unstripped) process environment and never exposes it to the LLM.
        Fixed destination URL — not LLM-controlled — so no SSRF surface.
        """
        if not re.match(r'^[a-fA-F0-9]{64}$', sha256 or ""):
            return f"ERROR: invalid sha256 {sha256!r} — must be 64 hex characters"
        try:
            resolved = self._confine_to_workspace(dest)
        except Exception as e:
            return f"ERROR: {e}"

        api_key = os.environ.get("MALWAREBAZAAR_API_KEY", "")
        if not api_key:
            return "ERROR: MALWAREBAZAAR_API_KEY not set in the harness environment"

        try:
            import requests
        except ImportError:
            return "ERROR: requests library not available"

        try:
            resp = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                headers={"Auth-Key": api_key},
                data={"query": "get_file", "sha256_hash": sha256},
                timeout=(_FETCH_CONNECT_TIMEOUT, _FETCH_READ_TIMEOUT),
                stream=True,
            )
        except requests.RequestException as e:
            return f"ERROR: MalwareBazaar request failed: {e}"

        if resp.status_code != 200:
            resp.close()
            return f"ERROR: MalwareBazaar HTTP {resp.status_code}"

        total = 0
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            with open(resolved, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > _MAX_FETCH_BYTES:
                        resolved.unlink(missing_ok=True)
                        return f"ERROR: download exceeded {_MAX_FETCH_BYTES} byte cap — aborted"
                    f.write(chunk)
        finally:
            resp.close()
        return f"OK — fetched {total} bytes from MalwareBazaar -> {resolved}"

    def _owned_task_id(self, raw) -> int:
        """
        Parse a model-supplied task id and, when a ledger is present, refuse
        any id this run did not submit (SG-AUTH-01: CAPE ids are sequential
        and the client holds a superuser token, so a guessed neighbour would
        otherwise read another project's analysis).
        """
        if isinstance(raw, bool) or raw is None:
            raise ValueError(f"task_id must be an integer, got {raw!r}")
        task_id = int(raw)
        if self.ctx is not None and not self.ctx.owns_task(task_id):
            raise ValueError(
                f"task {task_id} was not submitted by this run "
                f"(known: {[t.task_id for t in self.ctx.tasks] or 'none'})"
            )
        return task_id

    def _tool_cape_submit(self, call: dict) -> str:
        if not self.cape_client:
            return "ERROR: no CAPE client configured for this agent"
        sample_path = call.get("sample_path", "")
        raw_options = {
            "package":         call.get("package"),
            "timeout":         call.get("timeout"),
            "options":         call.get("options"),
            "machine":         call.get("machine"),
            "memory":          call.get("memory"),
            "enforce_timeout": call.get("enforce_timeout"),
            "tags":            call.get("tags"),
            "priority":        call.get("priority"),
            "platform":        call.get("platform"),
        }
        options = {k: v for k, v in raw_options.items() if v is not None}

        note = ""
        if self.ctx is not None:
            # SG-DATA-03: the file that goes to CAPE is the one the
            # controller pinned, never a path the model chose. The model's
            # argument is accepted only as a hint and overridden with a note
            # so it can see what actually happened.
            if not self.ctx.has_sample:
                return "ERROR: no sample is bound to this run; nothing to submit"
            identity = self.ctx.sample
            if not identity.matches(identity.path):
                return (f"ERROR: bound sample {identity.path} no longer resolves to "
                        f"the pinned inode — refusing to submit")
            if sample_path and Path(sample_path) != identity.path:
                note = (f" (note: sample_path {sample_path!r} ignored; the run's "
                        f"pinned sample {identity.path} was submitted)")
            sample_path = str(identity.path)
            # SG-NET-01: the route reaching CAPE is the controller's policy,
            # sent as its own field rather than folded into free-text options.
            options["route"] = self.ctx.route_policy
        elif not sample_path:
            return "ERROR: cape_submit requires 'sample_path'"

        try:
            task_id = self.cape_client.submit_file(sample_path, options)
        except Exception as e:
            return f"ERROR: CAPE submit failed: {e}"

        warnings_getter = getattr(self.cape_client, "submission_warnings", None)
        if callable(warnings_getter):
            try:
                warnings = warnings_getter(task_id)
                if warnings:
                    note += " WARNING: backend did NOT apply: " + "; ".join(warnings)
            except Exception:
                # Diagnostic failure must not lose the already-issued receipt.
                note += " WARNING: could not retrieve backend option warnings"

        if self.ctx is not None:
            # SG-CTL-01: the receipt enters the ledger here and nowhere else.
            # The spec mirror below is display only; _validate() and every
            # host operation read the ledger.
            try:
                pass_number = len(self.ctx.tasks) + 1
                receipt = self.ctx.record_task(
                    task_id, pass_number=pass_number,
                    route=self.ctx.route_policy,
                    machine=options.get("machine"),
                )
            except LedgerError as e:
                self.log.error(self.agent_name,
                               f"CAPE task {task_id!r} submitted but refused by ledger: {e}")
                return (f"ERROR: CAPE accepted the submission as task {task_id!r} but the "
                        f"run ledger refused to record it ({e}). Do not submit again; "
                        f"call finish() and report this.")
            # SG-NET-01, second half: read the route back from the task
            # record and record whether CAPE actually accepted the policy.
            # A read-back failure is recorded as unverified, not ignored.
            effective = None
            try:
                getter = getattr(self.cape_client, "get_task_route", None)
                effective = getter(receipt.task_id) if getter else None
            except Exception as e:
                self.log.warning(self.agent_name,
                                 f"Route read-back for task {receipt.task_id} failed: {e}")
            route_ok = self.ctx.confirm_task_route(receipt.task_id, effective)
            if not route_ok:
                self.log.error(self.agent_name,
                               f"CAPE task {receipt.task_id}: requested route "
                               f"{receipt.route!r} but CAPE reports {effective!r} — "
                               f"this task cannot count as a verified run")
                note += (f" WARNING: CAPE did not confirm route {receipt.route!r} "
                         f"(reported {effective!r}); the harness will not accept this "
                         f"task's report. Say so with log_observation and finish.")
            key = "cape_submission.pass1_task_id" if pass_number == 1 \
                  else "cape_submission.pass2_task_id"
            try:
                self.spec.set(key, receipt.task_id, actor="controller")
                self.spec.set("executor.passes_completed", len(self.ctx.tasks),
                              actor="controller")
            except (SpecPermissionError, SpecSchemaError) as e:
                self.log.warning(self.agent_name, f"Could not mirror task receipt: {e}")
            self.log.info(self.agent_name,
                          f"Ledger recorded CAPE task {receipt.task_id} "
                          f"(pass {pass_number}, route={receipt.route})")
        return f"OK — submitted {sample_path}. task_id={task_id}{note}"

    def _tool_cape_status(self, call: dict) -> str:
        if not self.cape_client:
            return "ERROR: no CAPE client configured for this agent"
        task_id = call.get("task_id")
        if task_id is None:
            return "ERROR: cape_status requires 'task_id'"
        try:
            task_id = self._owned_task_id(task_id)
        except ValueError as e:
            return f"ERROR: {e}"
        try:
            status = self.cape_client.get_task_status(task_id)
        except Exception as e:
            return f"ERROR: status check for task {task_id} failed: {e}"
        return f"task_id={task_id} status={status}"

    def _tool_cape_fetch_report(self, call: dict) -> str:
        if not self.cape_client:
            return "ERROR: no CAPE client configured for this agent"
        task_id = call.get("task_id")
        if task_id is None:
            return "ERROR: cape_fetch_report requires 'task_id'"
        try:
            task_id = self._owned_task_id(task_id)
        except ValueError as e:
            return f"ERROR: {e}"
        try:
            report = self.cape_client.get_report(task_id)
        except Exception as e:
            return f"ERROR: report fetch for task {task_id} failed: {e}"

        dest = call.get("save_to") or f"cape_report_{task_id}.json"
        try:
            resolved = self._confine_to_workspace(dest)
            resolved.write_text(json.dumps(report))
        except Exception as e:
            return f"ERROR writing report to {dest}: {e}"

        signal_info = ""
        if hasattr(self.cape_client, "report_has_signal"):
            try:
                signal_info = f" signal={self.cape_client.report_has_signal(report)}"
            except Exception:
                pass
        return f"OK — report for task {task_id} saved to {resolved}.{signal_info}"

    def _tool_cape_service_check(self) -> str:
        """
        Fixed, non-interpolated command — the only Docker-touching path left
        after P0-1/P0-2 route submit/status/report through REST. No
        LLM-controlled string content reaches this subprocess call at all.
        """
        try:
            # argv straight into the container — no `bash -c`, so the static
            # "no shell grammar anywhere" property holds for this path too.
            proc = subprocess.run(
                ["docker", "exec", "cape", "systemctl", "is-active",
                 "cape.service", "cape-web.service", "cape-processor.service"],
                capture_output=True, text=True, timeout=30, env=_minimal_env(),
            )
        except subprocess.TimeoutExpired:
            return "ERROR: service check timed out after 30s"
        except FileNotFoundError:
            return "ERROR: docker binary not found on this host"
        out = (proc.stdout + proc.stderr).strip() or f"(exit code {proc.returncode})"
        return out[:MAX_SHELL_OUTPUT]

    def _tool_cape_vm_start(self, vm_name: str) -> str:
        """
        Only a regex-validated VM name reaches the subprocess argv — never
        a free-form LLM-authored command string.
        """
        if not re.match(r'^[A-Za-z0-9_.-]{1,64}$', vm_name or ""):
            return f"ERROR: invalid vm_name {vm_name!r} — refused"
        # SG-CONC-01: same allowlist and lease rule as CapeHostOps. This tool
        # used to be a second, unguarded path to `virsh start` that bypassed
        # both; a model-reachable tool must not be weaker than the harness.
        if vm_name not in ALLOWED_VMS:
            return (f"ERROR: {vm_name!r} is not an analysis VM this harness manages "
                    f"(allowed: {sorted(ALLOWED_VMS)})")
        if self.ctx is not None:
            try:
                self.ctx.require_vm_lease(vm_name)
            except LedgerError as e:
                return f"ERROR: {e}"
        try:
            proc = subprocess.run(
                ["docker", "exec", "cape", "virsh", "start", vm_name],
                capture_output=True, text=True, timeout=30, env=_minimal_env(),
            )
        except subprocess.TimeoutExpired:
            return f"ERROR: virsh start {vm_name} timed out after 30s"
        except FileNotFoundError:
            return "ERROR: docker binary not found on this host"
        out = (proc.stdout + proc.stderr).strip() or f"(exit code {proc.returncode})"
        return out[:MAX_SHELL_OUTPUT]

    # ------------------------------------------------------------------

    def _run_argv(self, argv: list, timeout: int = 60) -> str:
        """
        Fixed-argv subprocess helper for analyze_sample operations that need
        a real external binary. shell=False and a list of literal arguments
        — no string is ever interpolated into a shell command line, so
        there is no injection surface here regardless of what the caller
        passes as individual argv elements. Same timeout+process-group-kill
        discipline the old run_shell used (CTL-07) and the same minimal
        environment (CTL-08).
        """
        try:
            proc = subprocess.Popen(
                argv,
                stdout            = subprocess.PIPE,
                stderr            = subprocess.PIPE,
                text              = True,
                env               = _minimal_env(),
                start_new_session = True,
            )
        except FileNotFoundError:
            return f"ERROR: {argv[0]} not available on this image"
        except Exception as e:
            return f"ERROR: {e}"

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            return f"ERROR: {argv[0]} timed out after {timeout}s (process group terminated)"

        output = (stdout or "") + (stderr or "")
        if not output:
            output = f"(exit code {proc.returncode})"
        if len(output) > MAX_SHELL_OUTPUT:
            output = output[:MAX_SHELL_OUTPUT] + f"\n... [truncated, {len(output)} total chars]"
        return output

    # ------------------------------------------------------------------
    # analyze_sample — CTL-01 typed operation broker (replaces run_shell)
    # ------------------------------------------------------------------

    def _tool_analyze_sample(self, call: dict) -> str:
        operations = {
            "identify":           self._op_identify,
            "file":                self._op_file,
            "zip_list":            self._op_zip_list,
            "zip_extract":         self._op_zip_extract,
            "pe_info":             self._op_pe_info,
            "pe_exports":          self._op_pe_exports,
            "macho_info":          self._op_macho_info,
            "apk_info":            self._op_apk_info,
            "ole_macros":          self._op_ole_macros,
            "ole_meta":            self._op_ole_meta,
            "python_ast_summary":  self._op_python_ast_summary,
            "find_files":          self._op_find_files,
            "strings":             self._op_strings,
            "strings_utf16":       self._op_strings_utf16,
            "readelf_headers":     self._op_readelf_headers,
            "readelf_dynamic":     self._op_readelf_dynamic,
            "readelf_symbols":     self._op_readelf_symbols,
            "nm_dynamic":          self._op_nm_dynamic,
            "upx_test":            self._op_upx_test,
            "yara_scan":           self._op_yara_scan,
            "diec":                self._op_diec,
            "archive_list":        self._op_archive_list,
            "archive_extract":     self._op_archive_extract,
            "apktool_unpack":      self._op_apktool_unpack,
            "grep":                self._op_grep,
            "pcap_top_talkers":    self._op_pcap_top_talkers,
            "pcap_dns_queries":    self._op_pcap_dns_queries,
            "pcap_tls_sni":        self._op_pcap_tls_sni,
            "pdf_id":              self._op_pdf_id,
        }
        operation = call.get("operation", "")
        handler = operations.get(operation)
        if handler is None:
            return (
                f"ERROR: unknown analyze_sample operation {operation!r}. "
                f"Valid operations: {', '.join(sorted(operations))}"
            )
        path = call.get("path", "")
        options = call.get("options") or {}
        try:
            resolved = self._confine_analysis_path(path)
        except ValueError as e:
            return f"ERROR: {e}"

        # Strongest containment: run the operation in a --network none, no-socket
        # sidecar (a parser RCE has nothing to exfiltrate through and no podman
        # socket to abuse). Falls back to the in-process fork+setuid-nobody
        # sandbox when container mode is off (tests, host runs).
        if _ANALYZE_IN_CONTAINER:
            return self._run_operation_in_container(operation, resolved, options)

        sandboxed = (
            operation not in _SANDBOX_EXEMPT_WRITE_OPS
            and os.environ.get("AMSA_SKIP_SAMPLE_SANDBOX", "") not in ("1", "true")
        )
        try:
            if sandboxed:
                return self._run_operation_sandboxed(handler, resolved, options)
            return handler(resolved, options)
        except Exception as e:
            return f"ERROR running {operation} on {path}: {e}"

    def _run_operation_in_container(self, operation: str, resolved: Path, options: dict) -> str:
        """
        Run one analyze_sample operation in a disposable --network none sidecar.
        Containment is enforced by the mounts and the container flags, not by
        trusting the parser. Inspection gets a read-only workspace; only the
        explicit extraction operations need a writable workspace. Reuses the
        real handlers via run_analyze_op_standalone.
        """
        workspace = self.spec.workspace.resolve()
        opdir = workspace / ".analyze"
        opdir.mkdir(parents=True, exist_ok=True)
        sample_path = None
        if self.ctx is not None and getattr(self.ctx, "has_sample", False):
            sample_path = str(self.ctx.sample.path)
        else:
            sample_path = self.spec.get("sample.path")
        req = {"operation": operation, "path": str(resolved), "options": options,
               "workspace": str(workspace), "sample_path": sample_path,
               "repo": _REPO_ROOT}
        reqfile = opdir / f"req_{os.getpid()}_{int(time.time()*1000)}.json"
        reqfile.write_text(json.dumps(req))

        workspace_mode = "rw" if operation in _SANDBOX_EXEMPT_WRITE_OPS else "ro"
        mounts = ["-v", f"{_REPO_ROOT}:{_REPO_ROOT}:ro",
                  "-v", f"{workspace}:{workspace}:{workspace_mode}"]
        # Mount the sample read-only if it lives outside the workspace.
        try:
            resolved.relative_to(workspace)
        except ValueError:
            if resolved.exists():
                mounts += ["-v", f"{resolved}:{resolved}:ro"]
        argv = [*_ANALYZE_PODMAN, "run", "--rm",
                "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=1g,exec",
                "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                "--memory", "2g", "--pids-limit", "256",
                *mounts, _ANALYZE_IMAGE,
                "python3", f"{_REPO_ROOT}/sandbox_infra/analyze/run_op.py", str(reqfile)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=180,
                                  env=_minimal_env())
        except subprocess.TimeoutExpired:
            return f"ERROR: {operation} timed out after 180s in the analysis sidecar"
        except FileNotFoundError:
            return "ERROR: container engine not found for the analysis sidecar"
        finally:
            try:
                reqfile.unlink()
            except OSError:
                pass
        if proc.returncode != 0:
            return (f"ERROR running {operation} in sidecar (exit {proc.returncode}): "
                    f"{(proc.stderr or '')[:300]}")
        return proc.stdout[:_result_cap('analyze_sample')] if proc.stdout else \
            f"(no output from {operation})"

    def _run_operation_sandboxed(self, handler, path: Path, options: dict) -> str:
        """
        DATA-01 mitigation (see module docstring above _drop_privileges_
        and_limit_resources): runs `handler(path, options)` in a forked
        child with resource limits and a dropped UID, communicating the
        result back over a pipe as JSON so a parser crash, a resource-limit
        kill, or an unreadable-file permission error all surface as a
        clean ERROR string to the caller rather than taking down the
        harness process itself.
        """
        read_fd, write_fd = os.pipe()
        pid = os.fork()

        if pid == 0:
            os.close(read_fd)
            try:
                _drop_privileges_and_limit_resources()
                try:
                    result = handler(path, options)
                    payload = json.dumps({"ok": True, "result": result})
                except BaseException as e:
                    payload = json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"})
            except BaseException as e:
                payload = json.dumps({"ok": False, "error": f"sandbox setup failed: {e}"})
            data = payload.encode("utf-8", errors="replace")
            view = memoryview(data)
            try:
                while view:
                    n = os.write(write_fd, view)
                    view = view[n:]
            finally:
                os.close(write_fd)
            os._exit(0)

        os.close(write_fd)
        chunks = []
        try:
            while True:
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(read_fd)
        _, status = os.waitpid(pid, 0)

        raw = b"".join(chunks)
        if not raw:
            if os.WIFSIGNALED(status):
                sig = os.WTERMSIG(status)
                return (f"ERROR: analysis subprocess was killed by signal {sig} "
                        f"(likely a resource limit — CPU {_SANDBOX_CPU_SECONDS}s / "
                        f"memory {_SANDBOX_MEM_BYTES // (1024*1024)}MB — was hit)")
            return f"ERROR: analysis subprocess produced no output (exit status {status})"
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            return f"ERROR: analysis subprocess produced unparseable output: {raw[:500]!r}"
        if not parsed.get("ok"):
            return f"ERROR: {parsed.get('error', 'unknown sandboxed-operation failure')}"
        return parsed.get("result", "")

    # --- in-process operations (no subprocess) ---------------------------

    def _op_identify(self, path: Path, options: dict) -> str:
        size = path.stat().st_size
        h = hashlib.sha256()
        with open(path, "rb") as f:
            magic = f.read(16)
            h.update(magic)
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return f"size={size} bytes\nsha256={h.hexdigest()}\nmagic_hex={magic.hex()}"

    def _op_zip_list(self, path: Path, options: dict) -> str:
        try:
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
                lines = [f"{len(infos)} member(s):"]
                for info in infos[:200]:
                    lines.append(f"  {info.filename}  ({info.file_size} bytes)")
        except zipfile.BadZipFile as e:
            return f"ERROR: not a valid zip: {e}"
        return "\n".join(lines)[:MAX_SHELL_OUTPUT]

    def _op_zip_extract(self, path: Path, options: dict) -> str:
        dest = options.get("dest")
        if not dest:
            return "ERROR: zip_extract requires options.dest"
        dest_path = self._confine_to_workspace(dest)
        dest_path.mkdir(parents=True, exist_ok=True)
        password = options.get("password")
        pwd_bytes = password.encode() if password else None

        # Same zip-bomb defense as the DATA-06 fix: cap member count,
        # per-member size, and compression ratio before extracting.
        max_members, max_member_bytes, max_ratio = 500, 200 * 1024 * 1024, 100
        try:
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
                if len(infos) > max_members:
                    return (f"ERROR: {len(infos)} members exceeds {max_members} "
                            f"cap — refused (possible zip bomb)")
                dest_resolved = dest_path.resolve()
                for info in infos:
                    if info.file_size > max_member_bytes:
                        return (f"ERROR: member {info.filename} size "
                                f"{info.file_size} exceeds {max_member_bytes} byte cap")
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > max_ratio:
                        return (f"ERROR: member {info.filename} compression ratio "
                                f"{ratio:.1f}:1 exceeds {max_ratio}:1 cap (likely zip bomb)")
                    target = (dest_path / info.filename).resolve()
                    if not target.is_relative_to(dest_resolved):
                        return (f"ERROR: member {info.filename} would extract "
                                f"outside dest — refused")
                zf.extractall(dest_path, pwd=pwd_bytes)
                names = [i.filename for i in infos]
        except RuntimeError as e:
            return f"ERROR: {e} (wrong password?)"
        except zipfile.BadZipFile as e:
            return f"ERROR: not a valid zip: {e}"
        return f"OK — extracted {len(names)} member(s) to {dest_path}: {', '.join(names[:20])}"

    def _op_pe_info(self, path: Path, options: dict) -> str:
        try:
            import pefile
        except ImportError:
            return "ERROR: pefile not available on this image"
        try:
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ])
        except Exception as e:
            return f"ERROR: {e}"
        lines = [
            f"machine={hex(pe.FILE_HEADER.Machine)}",
            f"timestamp={pe.FILE_HEADER.TimeDateStamp}",
            f"entry_point={hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}",
            "sections:",
        ]
        for s in pe.sections:
            name = s.Name.decode(errors="replace").rstrip("\x00")
            lines.append(f"  {name}  size={s.SizeOfRawData}  entropy={s.get_entropy():.2f}")
        lines.append("imports:")
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:30]:
            dll = entry.dll.decode(errors="replace")
            funcs = [imp.name.decode(errors="replace") for imp in entry.imports if imp.name][:10]
            lines.append(f"  {dll}: {', '.join(funcs)}")
        return "\n".join(lines)[:MAX_SHELL_OUTPUT]

    def _op_pe_exports(self, path: Path, options: dict) -> str:
        try:
            import pefile
        except ImportError:
            return "ERROR: pefile not available on this image"
        try:
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ])
        except Exception as e:
            return f"ERROR: {e}"
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if not exports:
            return "no export table"
        names = [e.name.decode(errors="replace") for e in exports.symbols if e.name]
        return f"{len(names)} export(s):\n" + "\n".join(names[:200])

    def _op_macho_info(self, path: Path, options: dict) -> str:
        try:
            from macholib.MachO import MachO
        except ImportError:
            return "ERROR: macholib not available on this image"
        try:
            m = MachO(str(path))
        except Exception as e:
            return f"ERROR: {e}"
        lines = []
        for header in m.headers:
            lines.append(f"cputype={header.header.cputype} filetype={header.header.filetype}")
            for cmd in header.commands:
                if cmd[0].get_cmd_name() == "LC_LOAD_DYLIB":
                    dep = cmd[2]
                    dep = dep.decode(errors="replace") if isinstance(dep, bytes) else dep
                    lines.append(f"  LC_LOAD_DYLIB: {dep}")
        return "\n".join(lines)[:MAX_SHELL_OUTPUT] if lines else "no load commands found"

    def _op_apk_info(self, path: Path, options: dict) -> str:
        try:
            from androguard.misc import AnalyzeAPK
        except ImportError:
            return "ERROR: androguard not available on this image"
        try:
            a, d, dx = AnalyzeAPK(str(path))
        except Exception as e:
            return f"ERROR: {e}"
        lines = [
            f"package={a.get_package()}",
            f"min_sdk={a.get_min_sdk_version()}",
            f"permissions={a.get_permissions()[:20]}",
            f"activities={a.get_activities()[:5]}",
            f"services={a.get_services()[:5]}",
            f"receivers={a.get_receivers()[:5]}",
        ]
        return "\n".join(lines)[:MAX_SHELL_OUTPUT]

    def _op_ole_macros(self, path: Path, options: dict) -> str:
        try:
            from oletools.olevba import VBA_Parser
        except ImportError:
            return "ERROR: oletools not available on this image"
        try:
            vba = VBA_Parser(str(path))
            if not vba.detect_vba_macros():
                return "no VBA macros detected"
            lines = []
            for (_filename, _stream_path, vba_filename, vba_code) in vba.extract_macros():
                lines.append(f"--- {vba_filename} ---")
                lines.append(vba_code[:2000])
            return "\n".join(lines)[:MAX_SHELL_OUTPUT]
        except Exception as e:
            return f"ERROR: {e}"

    def _op_ole_meta(self, path: Path, options: dict) -> str:
        try:
            import olefile
        except ImportError:
            return "ERROR: oletools/olefile not available on this image"
        try:
            ole = olefile.OleFileIO(str(path))
            meta = ole.get_metadata()
            lines = []
            for attr in meta.SUMMARY_ATTRIBS + meta.DOCSUM_ATTRIBS:
                val = getattr(meta, attr, None)
                if val:
                    lines.append(f"{attr}={val}")
            return "\n".join(lines)[:MAX_SHELL_OUTPUT] or "no metadata found"
        except Exception as e:
            return f"ERROR: {e}"

    def _op_python_ast_summary(self, path: Path, options: dict) -> str:
        import ast
        try:
            source = path.read_text(errors="replace")
            tree = ast.parse(source)
        except SyntaxError as e:
            return f"ERROR: could not parse as Python: {e}"
        imports, calls = [], []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(n.name for n in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.append(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    # e.g. os.system(...), subprocess.run(...) — the dotted
                    # form is exactly the shape malware scripts use most,
                    # so a bare ast.Name check alone would miss it.
                    parts = []
                    n = node.func
                    while isinstance(n, ast.Attribute):
                        parts.append(n.attr)
                        n = n.value
                    if isinstance(n, ast.Name):
                        parts.append(n.id)
                    calls.append(".".join(reversed(parts)))
        return (f"imports: {sorted(set(imports))}\n"
                f"top-level calls: {sorted(set(calls))[:40]}")

    def _op_find_files(self, path: Path, options: dict) -> str:
        if not path.is_dir():
            return f"ERROR: {path} is not a directory"
        ext = options.get("extension")
        pattern = f"*{ext}" if ext else "*"
        results = []
        for p in path.rglob(pattern):
            if p.is_file():
                results.append(str(p.relative_to(path)))
            if len(results) >= 200:
                break
        return f"{len(results)} file(s):\n" + "\n".join(results)

    # --- fixed-argv subprocess operations ---------------------------------

    def _op_file(self, path: Path, options: dict) -> str:
        return self._run_argv(["file", "--brief", str(path)], timeout=15)

    def _op_strings(self, path: Path, options: dict) -> str:
        return self._run_argv(["strings", "-n", "6", str(path)], timeout=30)

    def _op_strings_utf16(self, path: Path, options: dict) -> str:
        return self._run_argv(["strings", "-n", "6", "-e", "l", str(path)], timeout=30)

    def _op_readelf_headers(self, path: Path, options: dict) -> str:
        return self._run_argv(["readelf", "-h", str(path)], timeout=15)

    def _op_readelf_dynamic(self, path: Path, options: dict) -> str:
        return self._run_argv(["readelf", "-d", str(path)], timeout=15)

    def _op_readelf_symbols(self, path: Path, options: dict) -> str:
        return self._run_argv(["readelf", "-s", str(path)], timeout=15)

    def _op_nm_dynamic(self, path: Path, options: dict) -> str:
        return self._run_argv(["nm", "-D", str(path)], timeout=15)

    def _op_upx_test(self, path: Path, options: dict) -> str:
        return self._run_argv(["upx", "-t", str(path)], timeout=15)

    def _op_yara_scan(self, path: Path, options: dict) -> str:
        rules_dir = Path(_YARA_RULES_DIR)
        if not rules_dir.is_dir():
            return f"ERROR: yara rules directory not found at {_YARA_RULES_DIR}"
        rule_files = sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
        if not rule_files:
            return f"ERROR: no .yar/.yara rule files found in {_YARA_RULES_DIR}"
        matches = []
        for rf in rule_files[:20]:
            out = self._run_argv(["yara", str(rf), str(path)], timeout=5)
            if out.strip() and not out.startswith("(exit code") and not out.startswith("ERROR"):
                matches.append(out.strip())
        return "\n".join(matches)[:MAX_SHELL_OUTPUT] if matches else "no matches"

    def _op_diec(self, path: Path, options: dict) -> str:
        return self._run_argv(["diec", str(path)], timeout=20)

    def _op_archive_list(self, path: Path, options: dict) -> str:
        return self._run_argv(["7z", "l", str(path)], timeout=30)

    def _op_archive_extract(self, path: Path, options: dict) -> str:
        dest = options.get("dest")
        if not dest:
            return "ERROR: archive_extract requires options.dest"
        dest_path = self._confine_to_workspace(dest)
        dest_path.mkdir(parents=True, exist_ok=True)
        # NOTE: unlike zip_extract, 7z has no built-in member/ratio cap here
        # (DATA-03 residual gap) — bounded only by the subprocess timeout.
        return self._run_argv(["7z", "x", str(path), f"-o{dest_path}", "-y"], timeout=120)

    def _op_apktool_unpack(self, path: Path, options: dict) -> str:
        dest = options.get("dest")
        if not dest:
            return "ERROR: apktool_unpack requires options.dest"
        dest_path = self._confine_to_workspace(dest)
        return self._run_argv(["apktool", "d", str(path), "-o", str(dest_path), "-f"], timeout=60)

    def _op_grep(self, path: Path, options: dict) -> str:
        pattern = options.get("pattern")
        if not pattern:
            return "ERROR: grep requires options.pattern"
        return self._run_argv(["grep", "-E", "-i", pattern, str(path)], timeout=15)

    def _op_pdf_id(self, path: Path, options: dict) -> str:
        return self._run_argv(["pdfid", str(path)], timeout=20)

    def _op_pcap_top_talkers(self, path: Path, options: dict) -> str:
        argv = ["tshark", "-r", str(path), "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport"]
        out = self._run_argv(argv, timeout=30)
        if out.startswith("ERROR"):
            return out
        from collections import Counter
        counts = Counter(l for l in out.splitlines() if l.strip())
        return "\n".join(f"{n:>6}  {l}" for l, n in counts.most_common(30))

    def _op_pcap_dns_queries(self, path: Path, options: dict) -> str:
        argv = ["tshark", "-r", str(path), "-Y", "dns.flags.response eq 0",
                "-T", "fields", "-e", "dns.qry.name"]
        return self._run_argv(argv, timeout=30)

    def _op_pcap_tls_sni(self, path: Path, options: dict) -> str:
        argv = ["tshark", "-r", str(path), "-Y", "tls.handshake.type == 1",
                "-T", "fields", "-e", "tls.handshake.extensions_server_name"]
        return self._run_argv(argv, timeout=30)


@dataclass(frozen=True)
class _AnalysisPathContext:
    """Only the path context required by analysis handlers; no spec I/O.

    A sidecar must not construct EnvironmentSpec in the controller workspace:
    its constructor persists an empty template over the live shared document.
    This adapter cannot save, reload, or mutate the controller's spec.
    """

    workspace: Path
    sample_path: str | None

    def get(self, key, default=None):
        return self.sample_path if key == "sample.path" else default


def run_analyze_op_standalone(operation, path, options, workspace, sample_path=None):
    """
    Execute one analyze_sample operation with a throwaway AgentLoop, reusing the
    real _op_* handlers and path confinement. Called inside the static-analysis
    sidecar (sandbox_infra/analyze/run_op.py); returns the operation's string.
    """
    # Keep the original sample's single-file read carve-out and extraction
    # destination confinement without creating or changing any shared spec.
    spec = _AnalysisPathContext(Path(workspace), str(sample_path) if sample_path else None)

    class _NoLog:
        def __getattr__(self, _):
            return lambda *a, **k: None

    loop = AgentLoop(llm=None, system_prompt="x", spec=spec,
                     log=_NoLog(), agent_name="Scout")
    return loop._tool_analyze_sample(
        {"operation": operation, "path": str(path), "options": options or {}})
