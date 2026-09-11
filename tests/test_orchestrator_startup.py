#!/usr/bin/env python3
"""
Orchestrator-level startup smoke test.

M1 shipped two defects that every existing test missed, because neither the
168 security regression tests nor the 28 canary tests ever construct an
`Orchestrator`:

  1. `import os` inside the stale-report cleanup loop made `os` function-local
     for the whole of `__init__`, so `os.chmod()` fifteen lines earlier raised
     `UnboundLocalError`. Inherited from the BASE edition.
  2. The M1 edit that added `RunContext` matched on
     `"from core.env_spec import EnvironmentSpec"`, but the real import line is
     column-aligned with extra spaces, so the replacement silently did nothing
     and `RunContext` was an undefined name.

Both are import/name errors that `compileall` cannot see — it checks syntax,
not name resolution. The lesson this file encodes: unit tests over modules do
not prove the program starts. Anything that runs at construction time needs a
test that actually constructs it.
"""

from __future__ import annotations

import sys
import tempfile
import types
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from orchestrator import Orchestrator  # noqa: E402
from core.run_context import RunContext  # noqa: E402


class _StubCAPEClient:
    """
    Stands in for CAPEClient at the Orchestrator boundary.

    `Orchestrator.__init__` builds a real client, and *both* modes reach
    outside the process to do it: `local` asserts /opt/CAPEv2 exists on this
    host, `rest` performs a live `GET {url}/apiv2/` connectivity check. So the
    pipeline object cannot be constructed at all on a machine that is not
    already a CAPE host or pointed at a running server.

    That is a design problem worth fixing separately — connectivity belongs in
    a `connect()` the run calls, not in a constructor — but this test is about
    Orchestrator start-up, so it stubs the boundary rather than standing up a
    CAPE.
    """

    def __init__(self):
        self.cfg = types.SimpleNamespace(
            mode="rest",
            url="http://127.0.0.1:8001",
            storage="/opt/CAPEv2/storage/analyses",
            container="cape",
            token="stub",
            timeout=300,
        )


@pytest.fixture(autouse=True)
def _stub_cape(monkeypatch):
    monkeypatch.setattr("orchestrator.build_cape_client", lambda path: _StubCAPEClient())


def _args(workspace: str, sample: str, cape_config: str = None) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        workspace=workspace,
        binary=sample,
        repo_url=None,
        url=None,
        # The workspace lives on NFS in this deployment and the DATA-04 guard
        # refuses that by default. A harmless canary is exactly the case the
        # guard is not aimed at, so the test opts in explicitly rather than
        # weakening the guard.
        allow_network_storage=True,
        llm_config=None,
        cape_config=cape_config,
    )


@pytest.fixture()
def workspace_and_sample(tmp_path: Path):
    sample = tmp_path / "canary.bin"
    sample.write_bytes(b"MZ harmless canary payload")
    ws = tmp_path / "ws"
    return str(ws), str(sample), None


def test_orchestrator_constructs(workspace_and_sample):
    """The whole point: the program must reach a constructed state."""
    ws, sample, cape = workspace_and_sample
    orch = Orchestrator(_args(ws, sample, cape))
    assert orch.ctx is not None
    assert isinstance(orch.ctx, RunContext)


def test_sample_is_pinned_at_startup(workspace_and_sample):
    """
    SG-DATA-02: identity is established before any agent exists, from the bytes
    the controller opened — not from a spec field an agent can later rewrite.
    """
    import hashlib

    ws, sample, cape = workspace_and_sample
    orch = Orchestrator(_args(ws, sample, cape))
    expected = hashlib.sha256(Path(sample).read_bytes()).hexdigest()

    assert orch.ctx.sample.sha256 == expected
    assert orch.ctx.sample.size_bytes == Path(sample).stat().st_size
    # Mirrored into the spec for display, by the controller.
    assert orch.spec.get("sample.sha256") == expected


def test_workspace_is_0700(workspace_and_sample):
    ws, sample, cape = workspace_and_sample
    Orchestrator(_args(ws, sample, cape))
    assert oct(Path(ws).stat().st_mode)[-3:] == "700"


def test_ledger_starts_fail_closed(workspace_and_sample):
    """
    A freshly constructed run holds no task, no VM lease, and a
    deny-by-default route — this is construction-time state only.

    The controller half is wired as of M2: cape_submit records receipts,
    the Executor takes the VM lease, and the orchestrator sets the route
    after Scout. tests/test_pipeline_smoke.py drives run() with fakes and
    asserts each of those against the ledger.
    """
    ws, sample, cape = workspace_and_sample
    orch = Orchestrator(_args(ws, sample, cape))

    assert orch.ctx.latest_task() is None
    assert orch.ctx.tasks == []
    assert orch.ctx.route_policy == "drop"
    assert orch.ctx.verified_report() is None


def test_stale_report_cleanup_runs(tmp_path: Path):
    """
    The cleanup loop that carried the `import os` shadowing. Exercising it
    means the bug cannot come back unnoticed.
    """
    sample = tmp_path / "canary.bin"
    sample.write_bytes(b"MZ harmless canary payload")
    ws = tmp_path / "ws"
    ws.mkdir()
    stale = ws / "cape_report_999.json"
    stale.write_text('{"stale": true}')

    Orchestrator(_args(str(ws), str(sample), None))
    assert not stale.exists(), "stale cape_report was not removed at startup"


def test_missing_binary_fails_fast(tmp_path: Path):
    ws = tmp_path / "ws"
    with pytest.raises(FileNotFoundError):
        Orchestrator(_args(str(ws), str(tmp_path / "does_not_exist.bin"),
                           None))


def test_nfs_guard_refuses_without_optin(workspace_and_sample, monkeypatch):
    """DATA-04: the guard must still bite when the operator has not opted in."""
    ws, sample, cape = workspace_and_sample
    monkeypatch.setattr("orchestrator._check_storage_is_local", lambda p: "nfs")
    args = _args(ws, sample, cape)
    args.allow_network_storage = False
    with pytest.raises(RuntimeError, match="network filesystem"):
        Orchestrator(args)
