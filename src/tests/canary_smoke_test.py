#!/usr/bin/env python3
"""
tests/canary_smoke_test.py — P0-10 canary smoke test (harmless, offline)

Exercises the harness-owned safety logic added/verified during the P0
remediation pass, WITHOUT needing a live CAPE/KVM instance — this
environment has neither (no /dev/kvm, no virsh, no reachable CAPE API).
No real or simulated malware is downloaded, executed, or submitted
anywhere; every assertion below runs against in-process objects with
mocked collaborators (fake CAPEClient, fake LLM).

This is NOT a substitute for full P0-10 sign-off. Actually validating the
pipeline end-to-end (P0-10's real requirement) needs a live CAPE/KVM
deployment and harmless canary *samples* run through the real submission
path — that must happen in an environment with the infrastructure this
sandbox lacks. What this file guards against is regression of the
harness-side safety invariants themselves:

  - P0-5: pipeline failures propagate as a falsy Orchestrator.run() (and
    therefore sys.exit(1)), never silently reported as success.
  - P0-4: a CAPE report whose sha256 doesn't match the submitted sample is
    quarantined, never handed to Analyst as the authoritative artefact.
  - P0-3: cape_submission's network= option is deterministically derived
    from network.mode by harness code, defaulting to network=none
    (no egress) when network.mode is missing or unrecognized.
  - P0-1: analyze_sample rejects any operation outside its fixed allowlist,
    and confines every path to the run's workspace (or the original
    sample's own path, read-only) — there is no general-purpose shell to
    escape from any more. The SSRF host validator rejects loopback/
    private/metadata addresses.
  - P0-8: the storage-locality check used to refuse NFS/CIFS workspaces
    correctly identifies this sandbox's own filesystem as non-network.

Run with:  python3 -m unittest tests/canary_smoke_test.py -v
(from the SandboxGEN package root)
"""

import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.env_spec import EnvironmentSpec
from core.run_context import RunContext
from core.workflow_log import WorkflowLog
from core.agent_loop import AgentLoop
from agents.executor import ExecutorAgent
from agents.architect import ArchitectAgent
from orchestrator import _check_storage_is_local, _NETWORK_FSTYPES


class _FakeLLM:
    def chat(self, **kwargs):
        return None


class _FakeCAPEClientMismatch:
    """cape_client stub whose report never matches the submitted sample."""

    def get_report_verified(self, task_id, expected_sha256=None):
        fake_report = {"target": {"file": {"sha256": "deadbeef" * 8}}}
        return fake_report, False, "deadbeef" * 8

    def report_has_signal(self, report):
        return {
            "process_count": 0, "signature_count": 0,
            "malscore": 0.0, "network_events": 0, "has_signal": False,
        }


def _make_workspace():
    d = Path(tempfile.mkdtemp(prefix="canary_"))
    return d


class TestExitCodeContract(unittest.TestCase):
    """P0-5: orchestrator.run() must return False (-> exit 1) on failure."""

    def test_run_returns_bool_type_is_enforced_by_signature(self):
        import inspect
        import orchestrator
        sig = inspect.signature(orchestrator.Orchestrator.run)
        # No parameters besides self — run() takes no stage outcome
        # overrides, so we can't call it without live agents. Instead we
        # assert the source encodes the AND-of-stages / exception-catches-
        # False contract textually, which is what actually changed here.
        src = inspect.getsource(orchestrator.Orchestrator.run)
        self.assertIn("pipeline_ok = False", src)
        self.assertIn("return pipeline_ok", src)
        # The per-attempt state machine is where the AND-of-stages lives now.
        attempt_src = inspect.getsource(orchestrator.Orchestrator._run_single_attempt)
        self.assertIn(
            "pipeline_ok = scout_ok and architect_ok and executor_ok and analyst_ok",
            attempt_src,
        )
        # tests/test_pipeline_smoke.py exercises run() itself with fakes; this
        # textual check only guards the exit-code contract's shape.

    def test_cli_exits_nonzero_on_falsy_run(self):
        import inspect
        import orchestrator
        src = inspect.getsource(orchestrator)
        self.assertIn("sys.exit(0 if Orchestrator(parsed).run() else 1)", src)


class TestReportProvenance(unittest.TestCase):
    """P0-4: a sha256 mismatch must quarantine, never become authoritative."""

    def setUp(self):
        self.workspace = _make_workspace()
        self.spec = EnvironmentSpec(self.workspace, "canary-run")
        self.log = WorkflowLog(self.workspace, "canary-run")
        sample = self.workspace / "canary_sample.bin"
        sample.write_bytes(b"harmless canary")
        self.ctx = RunContext(run_id="canary-run", workspace=self.workspace)
        self.ctx.bind_sample(sample)
        self.ctx.set_route_policy("drop")
        self.ctx.record_task(999, pass_number=2, route="drop")
        self.spec.set("sample.sha256", "cafebabe" * 8, actor="controller")

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_mismatched_report_is_quarantined_not_authoritative(self):
        executor = ExecutorAgent(
            spec=self.spec, log=self.log, llm=_FakeLLM(),
            workspace=self.workspace, architect=None,
            cape_client=_FakeCAPEClientMismatch(),
            ctx=self.ctx,
        )
        quality = executor._persist_report_authoritatively(999)

        self.assertFalse(quality["verified"])
        self.assertIsNone(self.spec.get("pass2.artefacts.cape_report"))
        self.assertIsNotNone(self.spec.get("pass2.artefacts.quarantined_report"))
        self.assertEqual(
            self.spec.get("pass2.artefacts.quarantined_report_task_id"), 999
        )
        self.assertFalse(self.spec.get("executor.report_sha256_verified"))


class TestNetworkDefaultDeny(unittest.TestCase):
    """P0-3: network= is recomputed from network.mode, default-deny."""

    def setUp(self):
        self.workspace = _make_workspace()
        self.spec = EnvironmentSpec(self.workspace, "canary-run")
        self.log = WorkflowLog(self.workspace, "canary-run")

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def _architect(self):
        return ArchitectAgent(
            spec=self.spec, log=self.log, llm=_FakeLLM(),
            workspace=self.workspace, cape_client=None,
        )

    def test_missing_network_mode_defaults_to_none(self):
        arch = self._architect()
        arch._enforce_network_policy()
        self.assertEqual(
            self.spec.get("cape_submission.network_mode_enforced"), "none"
        )
        self.assertIn("network=none", self.spec.get("cape_submission.options", ""))

    def test_nat_mode_maps_to_internet(self):
        self.spec.set("network.mode", "nat", actor="controller")
        arch = self._architect()
        arch._enforce_network_policy()
        self.assertEqual(
            self.spec.get("cape_submission.network_mode_enforced"), "internet"
        )

    def test_llm_written_network_option_is_overridden_not_trusted(self):
        # Simulate the LLM having written a permissive option while
        # network.mode is unset/unrecognized — the harness must win.
        self.spec.set("cape_submission.options", "network=internet,human=1", actor="controller")
        arch = self._architect()
        arch._enforce_network_policy()
        options = self.spec.get("cape_submission.options", "")
        self.assertIn("network=none", options)
        self.assertNotIn("network=internet", options)
        self.assertIn("human=1", options)  # unrelated options preserved


class _FakeLog:
    def trace(self, *a, **k): pass
    def tool_call(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass


class TestAnalyzeSampleAllowlistAndSSRF(unittest.TestCase):
    """P0-1: analyze_sample enforces a fixed operation allowlist and path
    containment (no general-purpose shell exists any more); SSRF is defended."""

    def setUp(self):
        self.workspace = _make_workspace()
        self.spec = EnvironmentSpec(self.workspace, "canary-run")
        self.loop = AgentLoop(llm=None, system_prompt="x", spec=self.spec,
                              log=_FakeLog(), agent_name="Test")

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_unknown_operation_is_rejected(self):
        result = self.loop._tool_analyze_sample(
            {"operation": "delete_everything", "path": str(self.workspace)}
        )
        self.assertIn("ERROR", result)
        self.assertIn("unknown analyze_sample operation", result)

    def test_legitimate_operations_are_recognized(self):
        f = self.workspace / "sample.txt"
        f.write_text("hello")
        for op in ("identify", "file", "strings", "find_files"):
            with self.subTest(op=op):
                result = self.loop._tool_analyze_sample(
                    {"operation": op, "path": str(f if op != "find_files" else self.workspace)}
                )
                self.assertNotIn("unknown analyze_sample operation", result)

    def test_path_outside_workspace_and_sample_path_is_refused(self):
        result = self.loop._tool_analyze_sample(
            {"operation": "identify", "path": "/etc/passwd"}
        )
        self.assertIn("ERROR", result)
        self.assertIn("resolves outside the run workspace", result)

    def test_path_inside_workspace_is_accepted(self):
        f = self.workspace / "sample.txt"
        f.write_text("hello")
        result = self.loop._tool_analyze_sample({"operation": "identify", "path": str(f)})
        self.assertIn("sha256=", result)

    def test_original_sample_path_is_readable_outside_workspace(self):
        outside = Path(tempfile.mkdtemp(prefix="canary_sample_"))
        try:
            sample = outside / "malware.bin"
            sample.write_bytes(b"MZ fake")
            self.spec.set("sample.path", str(sample), actor="controller")
            result = self.loop._tool_analyze_sample({"operation": "identify", "path": str(sample)})
            self.assertIn("sha256=", result)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_extraction_dest_cannot_use_the_sample_path_exception(self):
        # The sample.path read-only carve-out must never work as a *write*
        # destination — only _confine_to_workspace (strict) may authorize
        # a dest argument.
        outside = Path(tempfile.mkdtemp(prefix="canary_sample_"))
        try:
            sample_dir = outside / "sample_dir"
            sample_dir.mkdir()
            zip_path = self.workspace / "test.zip"
            import zipfile
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("payload.txt", "x")
            result = self.loop._tool_analyze_sample({
                "operation": "zip_extract",
                "path": str(zip_path),
                "options": {"dest": str(sample_dir)},
            })
            self.assertIn("ERROR", result)
            self.assertIn("resolves outside the run workspace", result)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_ssrf_validator_rejects_loopback_and_metadata(self):
        for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    AgentLoop._validate_fetch_host(url)

    def test_ssrf_validator_rejects_bad_scheme(self):
        with self.assertRaises(ValueError):
            AgentLoop._validate_fetch_host("ftp://example.com/")

    def test_ssrf_validator_fails_closed_on_garbage_input(self):
        with self.assertRaises(ValueError):
            AgentLoop._validate_fetch_host("not a url")


class TestSampleParsingSandbox(unittest.TestCase):
    """DATA-01 mitigation: read-only analyze_sample operations run in a
    resource-limited forked child rather than directly in the harness
    process, so a parser bug is contained to a disposable child."""

    def setUp(self):
        self.workspace = _make_workspace()
        self.spec = EnvironmentSpec(self.workspace, "canary-run")
        self.loop = AgentLoop(llm=None, system_prompt="x", spec=self.spec,
                              log=_FakeLog(), agent_name="Test")

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)
        os.environ.pop("AMSA_SKIP_SAMPLE_SANDBOX", None)

    def test_write_operations_are_exempt_from_sandboxing(self):
        from core.agent_loop import _SANDBOX_EXEMPT_WRITE_OPS
        self.assertEqual(
            _SANDBOX_EXEMPT_WRITE_OPS,
            {"zip_extract", "archive_extract", "apktool_unpack"},
        )

    def test_sandboxed_operation_returns_correct_result(self):
        f = self.workspace / "sample.txt"
        f.write_text("hello")
        result = self.loop._tool_analyze_sample({"operation": "identify", "path": str(f)})
        self.assertIn("sha256=", result)

    def test_sandboxed_operation_error_surfaces_cleanly(self):
        # A nonexistent path should error out from inside the forked child
        # (or before it) without taking down the harness process.
        result = self.loop._tool_analyze_sample({
            "operation": "identify",
            "path": str(self.workspace / "does_not_exist.bin"),
        })
        self.assertIn("ERROR", result)

    def test_skip_sandbox_env_var_still_produces_correct_result(self):
        os.environ["AMSA_SKIP_SAMPLE_SANDBOX"] = "1"
        f = self.workspace / "sample.txt"
        f.write_text("hello")
        result = self.loop._tool_analyze_sample({"operation": "identify", "path": str(f)})
        self.assertIn("sha256=", result)

    def test_resource_limit_constants_are_positive(self):
        from core.agent_loop import (
            _SANDBOX_CPU_SECONDS, _SANDBOX_MEM_BYTES,
            _SANDBOX_FSIZE_BYTES, _SANDBOX_NOFILE, _SANDBOX_NPROC,
        )
        for value in (_SANDBOX_CPU_SECONDS, _SANDBOX_MEM_BYTES,
                      _SANDBOX_FSIZE_BYTES, _SANDBOX_NOFILE, _SANDBOX_NPROC):
            self.assertGreater(value, 0)


class TestWallTimeBudget(unittest.TestCase):
    """CTL-10: a stage must not run forever — wall-clock time is a second,
    independent backstop alongside max_iterations (a single blocking tool
    call, e.g. a CAPE poll, doesn't advance the iteration counter)."""

    def setUp(self):
        self.workspace = _make_workspace()
        self.spec = EnvironmentSpec(self.workspace, "canary-run")

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_default_wall_seconds_is_a_positive_finite_budget(self):
        loop = AgentLoop(llm=_FakeLLM(), system_prompt="x", spec=self.spec,
                          log=_FakeLog(), agent_name="Test")
        self.assertGreater(loop.max_wall_seconds, 0)

    def test_zero_budget_aborts_before_exhausting_max_iterations(self):
        loop = AgentLoop(llm=_FakeLLM(), system_prompt="x", spec=self.spec,
                          log=_FakeLog(), agent_name="Test",
                          max_iterations=80, max_wall_seconds=0)
        result = loop.run("do the task")
        self.assertFalse(result["finished"])
        # A zero-second budget means the deadline is already past at
        # iteration 1 — the run must not burn anywhere near the full
        # 80-iteration budget.
        self.assertLess(result["iterations"], 10)

    def test_explicit_override_takes_precedence_over_default(self):
        loop = AgentLoop(llm=_FakeLLM(), system_prompt="x", spec=self.spec,
                          log=_FakeLog(), agent_name="Test",
                          max_wall_seconds=123)
        self.assertEqual(loop.max_wall_seconds, 123)


class TestPinnedDNSResolution(unittest.TestCase):
    """CTL-05: the actual HTTP connection fetch_url makes must go to the
    same address _validate_fetch_host() already validated as safe — not
    re-resolve the hostname independently (the DNS-rebinding TOCTOU gap)."""

    def test_pinned_hostname_resolves_to_the_pinned_ip(self):
        orig = socket.getaddrinfo
        with AgentLoop._pinned_resolution("example.invalid", "203.0.113.5"):
            infos = socket.getaddrinfo("example.invalid", 80, proto=socket.IPPROTO_TCP)
        self.assertTrue(any(info[4][0] == "203.0.113.5" for info in infos))
        # Must be restored afterward — not left patched process-wide.
        self.assertIs(socket.getaddrinfo, orig)

    def test_pinning_does_not_affect_other_hostnames(self):
        with AgentLoop._pinned_resolution("example.invalid", "203.0.113.5"):
            # A .invalid hostname (RFC 2606) is guaranteed never to
            # resolve — this hostname isn't the pinned one, so it must
            # still fail resolution normally rather than being silently
            # rewritten to the pinned address too.
            with self.assertRaises(socket.gaierror):
                socket.getaddrinfo("unrelated-host.invalid", 80)

    def test_restores_getaddrinfo_even_if_the_request_raises(self):
        orig = socket.getaddrinfo
        with self.assertRaises(RuntimeError):
            with AgentLoop._pinned_resolution("example.invalid", "203.0.113.5"):
                raise RuntimeError("simulated request failure")
        self.assertIs(socket.getaddrinfo, orig)


class TestStorageGuardrail(unittest.TestCase):
    """P0-8: local sandbox storage must not be misidentified as network."""

    def test_sandbox_own_filesystem_is_not_flagged_as_network(self):
        fstype = _check_storage_is_local(Path(tempfile.gettempdir()))
        self.assertNotIn(fstype, _NETWORK_FSTYPES)

    def test_network_fstypes_set_contains_expected_entries(self):
        for expected in ("nfs", "nfs4", "cifs"):
            self.assertIn(expected, _NETWORK_FSTYPES)


if __name__ == "__main__":
    unittest.main()
