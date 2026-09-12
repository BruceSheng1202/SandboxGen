#!/usr/bin/env python3
"""
core/spec_policy.py — field ownership, role ACL and value schema for the spec

SG-CTL-02 remediation, parts 2-4 of 5.

The old `EnvironmentSpec.set()` accepted any dotted path with any value from
any caller, and the harness then read authorization-bearing fields back out of
that document. This module is the policy the new setter enforces:

  1. CONTROLLER_OWNED — paths only the harness may write. An agent tool that
     reaches these gets a refusal, not a silent no-op, because a silent no-op
     lets the model believe it succeeded and act on that belief.
  2. ROLE_WRITABLE — which agent may write which subtree. The old prompt told
     each role which tools it had; nothing enforced it server-side.
  3. FIELD_TYPES — the expected type per path. Round-1 INT-11 notes that one
     wrong type breaks downstream code; SG-CTL-02 notes it is also a DoS.

The policy is deliberately a data table rather than logic spread across the
agents: an auditor should be able to read what each role can touch without
tracing call sites, and the security regression tests iterate this table
directly.
"""

from __future__ import annotations

from typing import Any, Optional


class SpecPermissionError(PermissionError):
    """A writer tried to touch a path it does not own."""


class SpecSchemaError(ValueError):
    """A value failed the schema for its path."""


# ── 1. Controller-owned paths ─────────────────────────────────────────────────
#
# These decide what the harness is allowed to do, so they live in RunContext and
# are mirrored into the spec read-only, for display. Every entry here appears in
# the audit as a field a model could rewrite to its advantage:
#
#   sample.path / sample.sha256          SG-DATA-02  bypass the "original
#                                                    sample" read exception
#   cape_submission.*task_id             SG-CTL-01   reach shell / other tenants
#   network.mode                         SG-NET-01   defeat the route policy
#   executor.passes_completed            SG-INT-01   self-certify success
#   executor.validation_failed           SG-CTL-01   steer the correction path
#   pass2.artefacts.cape_report          SG-INT-02   substitute a report
#   report                               SG-INT-02   substitute conclusions
#
CONTROLLER_OWNED: frozenset[str] = frozenset(
    {
        "run_id",
        "created_at",
        "sample.path",
        "sample.sha256",
        "sample.size_bytes",
        "sample.source",
        "sample.repo_url",
        "network.mode",
        "network.route_enforced",
        "cape_submission.pass1_task_id",
        "cape_submission.pass2_task_id",
        "cape_submission.final_task_id",
        "cape_submission.network_mode_enforced",
        "cape_submission.available_machines",
        "cape_submission.backend_capabilities",
        "cape_submission.actual",
        "sandbox.actual",
        "executor.passes_completed",
        "executor.final_task_id",
        "executor.validation_failed",
        "executor.validation_error",
        "executor.report_sha256_verified",
        "executor.report_sha256_seen",
        "executor.report_quality",
        "executor.report_fetch_error",
        "executor.run_dir",
        "pass2.artefacts.cape_report",
        "pass2.artefacts.cape_report_task_id",
        "pass2.artefacts.quarantined_report",
        "pass2.artefacts.quarantined_report_task_id",
        "report",
        "token_usage",
    }
)

# Whole subtrees the controller owns, for paths that are generated rather than
# enumerable (e.g. per-monitor artefact entries the executor records).
CONTROLLER_OWNED_PREFIXES: tuple[str, ...] = (
    "pass2.artefacts.",
    "provenance.",
    "sandbox.actual.",
    "cape_submission.actual.",
    "cape_submission.validation_errors",
)


# ── 2. Role ACL ───────────────────────────────────────────────────────────────
#
# Prefixes each agent role may write. A role absent from this table may write
# nothing. The controller writes through a separate entry point and is not
# subject to the ACL.
#
ROLE_WRITABLE: dict[str, tuple[str, ...]] = {
    "Scout": (
        "sample.format",
        "sample.os_target",
        "sample.architecture",
        "sample.packed",
        "sample.interpreter",
        "sample.file_type",
        "sample.pe_is_dll",
        # Proposal namespace. SG-CTL-02 remediation item 3: an agent that needs
        # to influence a controller-owned decision proposes a value here and
        # the controller validates and promotes it. Scout recommends a network
        # posture; `network.mode` — what actually gets submitted to CAPE as the
        # route — stays controller-owned so SG-NET-01's "the declared policy
        # never reached CAPE" cannot be reintroduced from the model side.
        "network.proposed_mode",
        # Same proposal pattern for the sample location in --url/--repo runs:
        # Scout names the file it downloaded, the controller confines the
        # path to the workspace, opens it, and pins the identity itself
        # (SG-DATA-02). `sample.path` stays controller-owned.
        "sample.proposed_path",
        # Scout's system prompt has always asked it to describe the guest
        # environment and the network posture it observed statically; the
        # first policy draft listed these under Architect only, so every one
        # of those writes came back REFUSED. Both roles may write them: Scout
        # proposes, Architect refines.
        "network.intercept_dns",
        "network.intercept_http",
        "network.c2_server",
        "network.reasoning",
        "environment.",
        "classification.",
        "sandbox.isolation",
        "sandbox.os",
        "sandbox.arch",
        "sandbox.ram_mb",
        "sandbox.disk_gb",
        "sandbox.reasoning",
        "monitors.",
        "scout.",
    ),
    "Architect": (
        "environment.",
        "network.intercept_dns",
        "network.intercept_http",
        "network.c2_server",
        "network.reasoning",
        "cape_submission.package",
        "cape_submission.timeout",
        "cape_submission.enforce_timeout",
        "cape_submission.options",
        "cape_submission.memory",
        "cape_submission.machine",
        "cape_submission.platform",
        "cape_submission.priority",
        # Free-text fields the Architect prompt asks for. They carry no
        # authority (nothing in the harness branches on them) so they are
        # role-writable; `available_machines` and the task IDs are not.
        "cape_submission.tags",
        "cape_submission.reasoning",
        "cape_submission.error",
        "host.",
        "architect.",
    ),
    "Executor": (
        "pass1.",
        "pass2.completed",
        "passes",
        "executor.current_pass",
        "executor.corrections",
        "executor.empty_data_retry_done",
        "executor.observations",
        "monitors.",
    ),
    "Analyst": (
        "analysis.",
        "classification.family",
        "classification.confidence",
        "analyst.",
    ),
}


# ── 2b. Role → tool ACL ───────────────────────────────────────────────────────
#
# SG-CTL-03 (round-2 main text): `AgentLoop._execute_tool` dispatched every
# tool for every role, so the tool list in each system prompt was a suggestion.
# This table is what the dispatcher checks. A role absent from it may call
# nothing except `finish`, so a test harness that instantiates the loop with a
# made-up role cannot reach a side-effecting tool by accident.
#
_COMMON_TOOLS: tuple[str, ...] = (
    "read_spec", "update_spec", "append_spec",
    "read_file", "write_file",
    "log_decision", "log_observation", "finish",
)

ROLE_TOOLS: dict[str, frozenset[str]] = {
    "Scout": frozenset(
        _COMMON_TOOLS + ("analyze_sample", "fetch_url", "clone_repo", "mb_lookup", "query_json")
    ),
    "Architect": frozenset(
        _COMMON_TOOLS + ("analyze_sample", "cape_service_check", "query_json")
    ),
    "Executor": frozenset(
        _COMMON_TOOLS + (
            "analyze_sample", "query_json",
            "cape_service_check", "cape_vm_start",
            "cape_submit", "cape_status", "cape_fetch_report",
        )
    ),
    "Analyst": frozenset(
        _COMMON_TOOLS + ("analyze_sample", "query_json")
    ),
}


def tool_allowed(role: str, tool: str) -> bool:
    """Whether `role` may invoke `tool`. `finish` is always allowed so a stage can end."""
    if tool == "finish":
        return True
    return tool in ROLE_TOOLS.get(role, frozenset())


# ── 3. Value schema ───────────────────────────────────────────────────────────
#
# Exact-path types. Anything not listed falls back to STRUCTURAL_LIMITS only.
#
FIELD_TYPES: dict[str, type | tuple[type, ...]] = {
    "sample.format": str,
    "sample.os_target": str,
    "sample.architecture": str,
    "sample.packed": bool,
    "sample.interpreter": str,
    "sample.file_type": str,
    "sample.pe_is_dll": bool,
    "network.proposed_mode": str,
    "sample.proposed_path": str,
    "network.c2_server": str,
    "network.reasoning": str,
    "cape_submission.tags": str,
    "cape_submission.reasoning": str,
    "cape_submission.error": str,
    "analysis.report": dict,
    "classification.type": str,
    "classification.confidence": str,
    "classification.family": str,
    "classification.basis": list,
    "sandbox.isolation": str,
    "sandbox.os": str,
    "sandbox.arch": str,
    "sandbox.ram_mb": int,
    "sandbox.disk_gb": int,
    "sandbox.reasoning": str,
    "network.intercept_dns": bool,
    "network.intercept_http": bool,
    "cape_submission.package": str,
    "cape_submission.timeout": int,
    "cape_submission.enforce_timeout": bool,
    "cape_submission.options": str,
    "cape_submission.memory": bool,
    "cape_submission.machine": str,
    "cape_submission.platform": str,
    "cape_submission.priority": int,
    "pass1.completed": bool,
    "pass1.observations": list,
    "pass1.duration_s": (int, float),
    "pass2.completed": bool,
    "passes": list,
    "executor.current_pass": int,
    "executor.corrections": list,
    "executor.empty_data_retry_done": bool,
    "monitors": dict,
}

# Enumerations, where a free string would let a model select behaviour the
# harness then acts on.
FIELD_ENUMS: dict[str, frozenset[str]] = {
    "classification.confidence": frozenset({"high", "medium", "low", "unknown"}),
    "cape_submission.platform": frozenset({"windows", "linux", "macos", "android"}),
    "network.proposed_mode": frozenset({"isolated", "fakenet", "nat", "internet"}),
    "sample.os_target": frozenset(
        {"windows", "linux", "macos", "android", "cross-platform", "unknown"}
    ),
}

# Numeric bounds. SG-CTL-01's acceptance criteria call for property tests with
# oversized integers; these are the limits those tests assert against.
FIELD_BOUNDS: dict[str, tuple[int, int]] = {
    "sandbox.ram_mb": (256, 65536),
    "sandbox.disk_gb": (1, 2048),
    "cape_submission.timeout": (10, 1800),
    "cape_submission.priority": (1, 3),
    "executor.current_pass": (0, 16),
}

# Structural limits applied to every value regardless of path. A model that
# cannot pick the field it writes can still try to make the document itself
# expensive to hold, serialise or send back through the next prompt.
MAX_KEY_DEPTH = 6
MAX_KEY_LENGTH = 160
MAX_STRING_LENGTH = 64 * 1024
MAX_LIST_LENGTH = 2048
MAX_VALUE_DEPTH = 8
MAX_VALUE_NODES = 4096


def _owned_by_controller(path: str) -> bool:
    if path in CONTROLLER_OWNED:
        return True
    return any(path.startswith(p) for p in CONTROLLER_OWNED_PREFIXES)


def _measure(value: Any, depth: int = 0) -> int:
    """Count nodes while enforcing depth; raises rather than recursing forever."""
    if depth > MAX_VALUE_DEPTH:
        raise SpecSchemaError(
            f"value nests deeper than {MAX_VALUE_DEPTH} levels"
        )
    if isinstance(value, dict):
        n = 1
        for k, v in value.items():
            if not isinstance(k, str):
                raise SpecSchemaError(f"object keys must be strings, got {type(k).__name__}")
            n += _measure(v, depth + 1)
        return n
    if isinstance(value, list):
        if len(value) > MAX_LIST_LENGTH:
            raise SpecSchemaError(
                f"list has {len(value)} entries, limit {MAX_LIST_LENGTH}"
            )
        return 1 + sum(_measure(v, depth + 1) for v in value)
    if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
        raise SpecSchemaError(
            f"string is {len(value)} chars, limit {MAX_STRING_LENGTH}"
        )
    return 1


def check_write(path: str, value: Any, actor: str) -> None:
    """
    Authorise and validate one spec write, or raise.

    `actor` is the agent role, or "controller" for harness-side writes. The
    caller passes its own identity — this is not a security boundary against
    harness code, it is a boundary against anything an agent can reach, which
    is exactly the `update_spec` / `append_spec` tool pair.
    """
    if not isinstance(path, str) or not path:
        raise SpecSchemaError(f"spec key must be a non-empty string, got {path!r}")
    if len(path) > MAX_KEY_LENGTH:
        raise SpecSchemaError(f"spec key is {len(path)} chars, limit {MAX_KEY_LENGTH}")

    parts = path.split(".")
    if len(parts) > MAX_KEY_DEPTH:
        raise SpecSchemaError(
            f"spec key {path!r} is {len(parts)} levels deep, limit {MAX_KEY_DEPTH}"
        )
    for p in parts:
        if not p:
            raise SpecSchemaError(f"spec key {path!r} has an empty path segment")
        if not (p.replace("_", "").replace("-", "").isalnum()):
            raise SpecSchemaError(
                f"spec key segment {p!r} in {path!r} is not alphanumeric"
            )

    if actor != "controller":
        if _owned_by_controller(path):
            raise SpecPermissionError(
                f"{actor} may not write {path!r}: this field is controller-owned. "
                "It is set by the harness from verified state and reported to you "
                "as a run fact."
            )
        allowed = ROLE_WRITABLE.get(actor)
        if allowed is None:
            raise SpecPermissionError(f"unknown role {actor!r} may not write the spec")
        if not any(
            path == a.rstrip(".") or path.startswith(a) for a in allowed
        ):
            raise SpecPermissionError(
                f"{actor} may not write {path!r}. Writable prefixes for this role: "
                + ", ".join(allowed)
            )

    _measure(value)

    expected = FIELD_TYPES.get(path)
    if expected is not None and value is not None:
        # bool is an int subclass; a bool where an int is wanted is a type error.
        if expected is int and isinstance(value, bool):
            raise SpecSchemaError(f"{path} expects int, got bool")
        if not isinstance(value, expected):
            names = (
                expected.__name__
                if isinstance(expected, type)
                else "/".join(t.__name__ for t in expected)
            )
            raise SpecSchemaError(
                f"{path} expects {names}, got {type(value).__name__}"
            )

    enum = FIELD_ENUMS.get(path)
    if enum is not None and value is not None and value not in enum:
        raise SpecSchemaError(
            f"{path} must be one of {sorted(enum)}, got {value!r}"
        )

    bounds = FIELD_BOUNDS.get(path)
    if bounds is not None and isinstance(value, int) and not isinstance(value, bool):
        lo, hi = bounds
        if not (lo <= value <= hi):
            raise SpecSchemaError(f"{path} must be within [{lo}, {hi}], got {value}")


def writable_paths_for(actor: str) -> tuple[str, ...]:
    """The prefixes a role may write, for prompt text and for error messages."""
    return ROLE_WRITABLE.get(actor, ())
