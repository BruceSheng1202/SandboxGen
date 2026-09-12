#!/usr/bin/env python3
"""
agents/executor.py — Executor Agent (CAPEv2 edition) with Self-Correction

Changes from original:
  - Added _diagnose_failure() — classifies WHY an analysis failed into
    one of 7 failure types
  - Added _correction_loop() — maps failure type → fix action and retries
  - Added _fix_*() methods — one per failure type
  - Architect.adjust() is now called with specific typed reasons
  - Retry budget: max 3 correction attempts per failure type
  - All correction decisions are written to spec under executor.corrections[]
"""

import glob
import json
import os
import time
from pathlib import Path
from core.agent_loop import AgentLoop
from core.backend_contract import is_qemu, submission_problems
from core.cape_client import CAPEClient
from core.host_ops import CapeHostOps, HostOpError
from core.run_context import RunContext, LedgerError

# How long this run may hold its analysis VM. Generous: a stage can take
# 40 minutes of wall clock and the correction loop can re-run it several
# times; the lease is released explicitly at the end of run() anyway.
VM_LEASE_TTL_SECONDS = 6 * 3600


# ── Failure type constants ────────────────────────────────────────────────────
F_VM_DOWN            = "VM_DOWN"
F_CAPE_SERVICE_DOWN  = "CAPE_SERVICE_DOWN"
F_WRONG_PACKAGE      = "WRONG_PACKAGE"
F_AGENT_UNREACHABLE  = "AGENT_UNREACHABLE"
F_SUBMISSION_ERROR   = "SUBMISSION_ERROR"
F_TIMEOUT_NO_DATA    = "TIMEOUT_NO_DATA"
F_REPORT_MISSING     = "REPORT_MISSING"
F_UNKNOWN            = "UNKNOWN"

MAX_CORRECTIONS_PER_TYPE = 3   # max retries for any single failure type
AGENT_IP_WIN   = "192.168.122.105"
AGENT_IP_LINUX = "192.168.122.106"
AGENT_PORT     = 8000


SYSTEM_PROMPT = r"""
You are the Executor Agent in AMSA — an Agentic Malware Sandbox Analyser.

YOUR GOAL:
Submit the malware to CAPEv2, monitor the analysis, and retrieve the results.
The configured backend handles execution, monitoring, and artefact collection.
Use backend_capabilities and available_machines as the actual contract.
qemu-tcg boots a fresh disposable Linux/Windows guest per submission; there is
no persistent CAPE Docker service or libvirt VM to start or restart for it.

YOUR FIRST ACTION IS ALWAYS TO READ THE SPEC.

CRITICAL INSTRUCTION — YOU MUST USE TOOL CALLS:
Every single response MUST contain at least one <tool_call> block.
NEVER respond with plain text only. NEVER explain what you are about to do
without also doing it via a tool call in the SAME response.
If you are thinking, also call a tool. No exceptions.
Failure to use tool calls means the pipeline stalls and the analysis fails.

CORRECT format — always use this:
<tool_call>
{"tool": "update_spec", "key": "pass1.completed", "value": true}
</tool_call>

WRONG — never do this:
Responding with only text and no <tool_call> block.

TOOL INTERFACE:
<tool_call>
{"tool": "cape_status", "task_id": 123}
</tool_call>

<tool_call>
{"tool": "update_spec", "key": "pass1.completed", "value": true}
</tool_call>

Available tools: analyze_sample, cape_service_check, cape_vm_start, cape_submit,
                 cape_status, cape_fetch_report, read_spec, update_spec,
                 append_spec, read_file, write_file, query_json, log_decision,
                 log_observation, finish

P0-1/P0-2: there is no general-purpose shell (audit CTL-01/CTL-04). All
CAPE/Docker interaction goes through the typed cape_* tools below — they
call the hardened CAPEClient (REST by default) rather than the LLM
constructing raw shell strings. analyze_sample is available for any static
re-inspection of the sample you need mid-run (see agents/scout.py's system
prompt for the full operation list), but CAPE submission/status/report
retrieval must always go through the cape_* tools, never analyze_sample.

═══════════════════════════════════════════════════════════════════════
STEP 1 — READ SPEC AND EXTRACT SUBMISSION PARAMETERS
═══════════════════════════════════════════════════════════════════════

read_spec() and extract:

  sample.path                    — absolute path to malware binary
  cape_submission.package        — analysis package (exe, dll, doc, …)
  cape_submission.machine        — VM label (or null for auto-select)
  cape_submission.platform       — windows | linux
  cape_submission.timeout        — analysis timeout in seconds
  cape_submission.memory         — bool
  cape_submission.enforce_timeout — bool
  cape_submission.options        — CAPE options string
  cape_submission.tags           — VM tags

Also read the CAPEv2 connection info from the environment.

═══════════════════════════════════════════════════════════════════════
STEP 2 — VERIFY CAPE IS RUNNING
═══════════════════════════════════════════════════════════════════════

Check the configured backend's readiness (for QEMU this checks configured
artifacts; guest startup is checked during submission):

  {"tool": "cape_service_check"}

If the VM needs starting:
  For a persistent CAPE deployment, use cape_vm_start with the compatible
  selected VM name. For qemu-tcg, submit directly; guests boot per task.
  There is no wait/sleep tool — just proceed to cape_submit. CAPE's own
  status-poll loop (Step 3 below) already tolerates the VM still booting,
  so nothing is lost by not waiting here explicitly.

If services are down, note it and proceed — the harness's own correction
loop restarts services/VMs between attempts if submission subsequently fails.

═══════════════════════════════════════════════════════════════════════
STEP 3 — SUBMIT TO CAPE (PASS 1 — QUICK CHECK)
═══════════════════════════════════════════════════════════════════════

For Pass 1, use a short timeout (60s):

  {"tool": "cape_submit", "sample_path": "{sample.path}", "package": "{package}", "timeout": 60, "options": "{options}"}

The result gives task_id directly (e.g. "OK — submitted ... task_id=5") —
no output parsing needed.

Poll for completion every 15 seconds (timeout 120s for Pass 1):
  {"tool": "cape_status", "task_id": <task_id>}

═══════════════════════════════════════════════════════════════════════
STEP 4 — ASSESS PASS 1 RESULTS
═══════════════════════════════════════════════════════════════════════

Fetch and inspect the report:
  {"tool": "cape_fetch_report", "task_id": <task_id>, "save_to": "pass1_report.json"}
  {"tool": "read_file", "path": "pass1_report.json"}

If Pass 1 succeeded (process tree shows execution):
  - Set pass1.completed = true
  - Proceed to Pass 2

If analysis failed, set pass1.adjustment_needed with one of these exact values:
  "WRONG_PACKAGE:<current_package>:<reason>"
  "TIMEOUT_NO_DATA:<current_timeout>:<reason>"
  "AGENT_UNREACHABLE:<reason>"
  "VM_DOWN:<reason>"

═══════════════════════════════════════════════════════════════════════
STEP 5 — SUBMIT TO CAPE (PASS 2 — FULL ANALYSIS)
═══════════════════════════════════════════════════════════════════════

  {"tool": "cape_submit", "package": "exe", "timeout": 120, "options": "network=none", "memory": false}

Replace these example values with the planned settings and actual run facts.
Only request options implemented by backend_capabilities; qemu-tcg does
not implement CAPE combo, extraction, injection, or memory-dump options.

Poll until completion. Timeout = timeout + 120 seconds.

═══════════════════════════════════════════════════════════════════════
STEP 6 — RETRIEVE AND STORE RESULTS
═══════════════════════════════════════════════════════════════════════

Once Pass 2 status = "reported":

  {"tool": "cape_fetch_report", "task_id": <task_id>, "save_to": "cape_report_<task_id>.json"}

(The harness independently re-fetches and sha256-verifies this report as
the authoritative artefact after you finish — see cape_fetch_report's
result for a quick signal preview, but do not treat your own fetch here as
final. The task_id was recorded by the harness when cape_submit returned;
it appears in the RUN FACTS block and you do not need to write it anywhere.)

═══════════════════════════════════════════════════════════════════════
STEP 7 — WRITE RESULTS TO SPEC
═══════════════════════════════════════════════════════════════════════

  update_spec("pass1.completed",  true)
  update_spec("pass2.completed",  true)

DO NOT try to write task IDs, sample paths, sample hashes, report paths or
network mode. Those are controller-owned: the harness records them itself from
the submit receipt it got back from CAPE, and reports them to you in the RUN
FACTS block. An update_spec call against one of them returns REFUSED and
changes nothing — retrying it wastes iterations. If a run fact looks wrong,
say so with log_observation instead of trying to overwrite it.

═══════════════════════════════════════════════════════════════════════
STEP 8 — FINISH
═══════════════════════════════════════════════════════════════════════

  finish("CAPEv2 analysis complete. Pass1 task={p1_id}. Pass2 task={p2_id}. Status=reported.")
"""


class ExecutorAgent:
    def __init__(self, spec, log, llm, workspace: Path,
                 architect, cape_client: CAPEClient,
                 ctx: RunContext,
                 host_ops: CapeHostOps = None,
                 max_passes: int = 2,
                 failure_context: str = ""):
        self.spec        = spec
        self.log         = log
        self.llm         = llm
        self.workspace   = workspace
        self.architect   = architect
        self.cape_client = cape_client
        self.max_passes  = max_passes
        self._correction_counts = {}   # failure_type → attempt count
        # Retry edition: controller-rendered summary of earlier attempts.
        self.failure_context = failure_context or ""

        # SG-CTL-01/02: the controller ledger, not the spec, is where this
        # agent reads task IDs and the sample identity from. `ctx` is required
        # so a caller cannot construct an Executor that falls back to the old
        # spec-derived behaviour.
        self.ctx      = ctx
        self.host_ops = host_ops or CapeHostOps(ctx)

    # ── Helpers ───────────────────────────────────────────────────────────────
    #
    # `_shell()` used to live here. It took a command string and ran it through
    # `subprocess.run(..., shell=True)`, and the recovery paths below built
    # those strings by interpolating CAPE task IDs that any agent could set via
    # `update_spec` — the SG-CTL-01 host-RCE path. Everything it did is now a
    # named, argv-only method on `CapeHostOps`. Do not reintroduce a
    # string-command helper here; `tests/test_sg_ctl_01_02.py` fails the build
    # on any `shell=` that is not a literal `False`.

    def _current_task_id(self):
        """
        The CAPE task this run is working on, from the controller ledger.

        Previously read as
        `spec.get("cape_submission.pass2_task_id") or spec.get(...pass1...)`,
        i.e. from a document the model could write. The ledger only ever holds
        IDs that came back from a submit this harness performed, already
        validated as positive ints.
        """
        latest = self.ctx.latest_task()
        return latest.task_id if latest else None

    def _record_correction(self, failure_type: str, action: str, outcome: str):
        """Append a correction event to the spec for traceability."""
        entry = {
            "failure_type": failure_type,
            "action":       action,
            "outcome":      outcome,
            "timestamp":    time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.spec.append("executor.corrections", entry, actor="controller")
        self.log.info("Executor",
                      f"[CORRECTION] {failure_type} → {action} → {outcome}")

    # ── Failure diagnosis ─────────────────────────────────────────────────────

    def _diagnose_failure(self) -> str:
        """
        Inspect the current system state and spec to classify the failure.
        Returns one of the F_* constants.
        """
        self.log.info("Executor", "Diagnosing failure...")

        if is_qemu(self.cape_client):
            health = self.cape_client.health_check()
            if not health.get("ready"):
                self.log.warning("Executor", f"QEMU backend unavailable: {health}")
                return F_UNKNOWN
            task_id = self._current_task_id()
            if task_id is None:
                return F_SUBMISSION_ERROR
            status = self.cape_client.get_task_status(task_id)
            if str(status).startswith("failed"):
                return F_SUBMISSION_ERROR
            try:
                quality = self.cape_client.report_has_signal(self.cape_client.get_report(task_id))
            except (ValueError, KeyError, FileNotFoundError):
                return F_REPORT_MISSING
            if quality.get("execution_valid") is False:
                return F_SUBMISSION_ERROR
            return F_TIMEOUT_NO_DATA if not quality.get("has_signal") else F_UNKNOWN

        # 1. Check CAPE services. `systemctl is-active` reports through its
        #    exit code; the old substring match on "inactive"/"failed" also
        #    matched the word appearing in an unrelated error line.
        svc_ok, svc_text = self.host_ops.services_active()
        if not svc_ok:
            self.log.info("Executor", f"Diagnosis: {F_CAPE_SERVICE_DOWN} (services={svc_text})")
            return F_CAPE_SERVICE_DOWN

        # 2. Check VM state
        vm_state = self.host_ops.vm_state(self._vm_for_platform())
        if vm_state in ("shut off", "paused", "unknown", "crashed"):
            self.log.info("Executor", f"Diagnosis: {F_VM_DOWN} (vm_state={vm_state})")
            return F_VM_DOWN

        # 3. Check agent reachability
        agent_ip = self._agent_ip_for_platform()
        if not self.host_ops.agent_reachable(agent_ip, AGENT_PORT):
            self.log.info("Executor", f"Diagnosis: {F_AGENT_UNREACHABLE} (agent={agent_ip})")
            return F_AGENT_UNREACHABLE

        # 4. Check if there's a task ID but report is missing. The ID comes
        #    from the controller ledger (SG-CTL-01), so it is an int this run
        #    submitted rather than a string the model chose.
        task_id = self._current_task_id()
        if task_id:
            if not self.host_ops.report_exists(task_id, self.cape_client.cfg.storage):
                self.log.info("Executor", f"Diagnosis: {F_REPORT_MISSING} (task={task_id})")
                return F_REPORT_MISSING

            # 5. Report exists — does it show any target behaviour? This used
            #    to shell out to an inline `python3 -c` inside the container
            #    and parse its stdout. Going through CAPEClient keeps the
            #    parsing in this process, where the size limits and schema
            #    checks live, and drops two more shell strings.
            try:
                report = self.cape_client.get_report(task_id)
                procs = (report.get("behavior") or {}).get("processes") or []
            except Exception as e:
                self.log.info("Executor", f"Diagnosis: {F_REPORT_MISSING} (fetch failed: {e})")
                return F_REPORT_MISSING

            if len(procs) == 0:
                status = str(self.cape_client.get_task_status(task_id) or "")
                # CAPE's failure states are failed_analysis / failed_processing /
                # failed_reporting; an exact match on "failed" never fired.
                if status.startswith("failed"):
                    self.log.info("Executor",
                                  f"Diagnosis: {F_SUBMISSION_ERROR} (status={status})")
                    return F_SUBMISSION_ERROR
                self.log.info("Executor", f"Diagnosis: {F_TIMEOUT_NO_DATA} (procs=0)")
                return F_TIMEOUT_NO_DATA

        # 6. Check spec for adjustment hint from Pass 1
        adjustment = self.spec.get("pass1.adjustment_needed", "")
        if adjustment:
            if "WRONG_PACKAGE" in adjustment:
                return F_WRONG_PACKAGE
            if "TIMEOUT" in adjustment:
                return F_TIMEOUT_NO_DATA
            if "AGENT" in adjustment:
                return F_AGENT_UNREACHABLE
            if "VM_DOWN" in adjustment:
                return F_VM_DOWN

        self.log.info("Executor", f"Diagnosis: {F_UNKNOWN}")
        return F_UNKNOWN

    # ── Fix actions ───────────────────────────────────────────────────────────

    def _vm_for_platform(self) -> str:
        """
        Which analysis VM this run's platform maps to.

        `cape_submission.platform` is Architect-writable, but `spec_policy`
        constrains it to a closed enum and this maps it onto the `ALLOWED_VMS`
        set, so no model-supplied string reaches libvirt either way.
        """
        os_target = self.spec.get("cape_submission.platform") or self.spec.get("sample.os_target")
        if os_target not in ("linux", "windows"):
            raise ValueError("No supported platform selected for VM recovery")
        if is_qemu(self.cape_client):
            return "qemu-" + os_target
        return "cuckoo2_linux" if os_target == "linux" else "cuckoo1"

    def _agent_ip_for_platform(self) -> str:
        os_target = self.spec.get("cape_submission.platform") or self.spec.get("sample.os_target")
        if os_target not in ("linux", "windows"):
            raise ValueError("No supported platform selected for agent recovery")
        return AGENT_IP_LINUX if os_target == "linux" else AGENT_IP_WIN

    def _fix_vm_down(self) -> bool:
        """Start the VM and wait for it to be ready."""
        vm = self._vm_for_platform()
        self.log.info("Executor", f"Fix: starting VM {vm}...")
        # The old command ended in `|| true`, so a libvirt refusal looked
        # identical to a VM that was already running. The result is inspected
        # instead, and a start that fails for a reason other than "already
        # running" is reported as such.
        started = self.host_ops.vm_start(vm)
        if not started.ok and "already active" not in started.combined.lower():
            self._record_correction(F_VM_DOWN, f"virsh start {vm}",
                                    f"start refused: {started.combined[:200]}")
            return False
        time.sleep(30)
        state = self.host_ops.vm_state(vm)
        ok = state == "running"
        self._record_correction(F_VM_DOWN, f"virsh start {vm}",
                                "running" if ok else f"still {state}")
        return ok

    def _fix_cape_service_down(self) -> bool:
        """Restart CAPE services."""
        self.log.info("Executor", "Fix: restarting CAPE services...")
        self.host_ops.restart_services()
        time.sleep(15)
        ok, svc_text = self.host_ops.services_active()
        self._record_correction(F_CAPE_SERVICE_DOWN,
                                "systemctl restart cape.*", svc_text)
        return ok

    def _fix_agent_unreachable(self) -> bool:
        """
        Revert the VM to its clean snapshot so the agent starts fresh.
        This handles the case where the agent process died inside the VM
        (e.g. encrypted by malware, as happened with Akira).
        """
        vm_name = self._vm_for_platform()

        # INF-08/09 fix: the snapshot name AND the revert mechanism must
        # match how each platform's start script actually created the
        # snapshot. Both windows_start.sh and linux_start.sh now create
        # "agent_ready" via `virsh snapshot-create-as` (a libvirt-managed
        # snapshot) — not `qemu-img snapshot -a` (a raw internal qcow2-file
        # snapshot). This used to read "clean_snapshot" for Linux, which
        # no start script ever created, so Linux recovery always failed.
        snapshot_name = "agent_ready"

        self.log.info("Executor",
                      f"Fix: reverting {vm_name} to '{snapshot_name}' snapshot...")

        # `virsh destroy` on an already-off VM exits non-zero; that is the one
        # failure this step tolerates, so it is named rather than swallowed by
        # a blanket `|| true`.
        destroyed = self.host_ops.vm_destroy(vm_name)
        if not destroyed.ok and "not running" not in destroyed.combined.lower():
            self._record_correction(
                F_AGENT_UNREACHABLE,
                f"virsh destroy {vm_name}",
                f"destroy refused: {destroyed.combined[:200]}",
            )
            return False
        time.sleep(5)

        reverted = self.host_ops.vm_snapshot_revert(vm_name, snapshot_name)
        if not reverted.ok:
            # SG-VM-01: a failed revert means the next analysis would run on a
            # VM whose state is unknown, so recovery stops here instead of
            # starting it anyway and reporting the agent as the only problem.
            self._record_correction(
                F_AGENT_UNREACHABLE,
                f"snapshot-revert {vm_name} to {snapshot_name}",
                f"revert failed: {reverted.combined[:200]}",
            )
            return False

        self.host_ops.vm_start(vm_name)
        time.sleep(60)   # Windows needs ~60s to boot

        ok = self.host_ops.agent_reachable(self._agent_ip_for_platform(), AGENT_PORT)
        self._record_correction(F_AGENT_UNREACHABLE,
                                f"revert {vm_name} to {snapshot_name} + restart",
                                "agent UP" if ok else "agent still DOWN")
        return ok

    def _adjust_submission(self, reason: str) -> bool:
        """Every Architect adjustment must pass the same configuration gate."""
        result = self.architect.adjust(reason)
        problems = submission_problems(
            self.spec, self.cape_client,
            self.ctx.sample.path if self.ctx.has_sample else self.spec.get("sample.path"),
        )
        if not isinstance(result, dict) or result.get("finished") is not True:
            problems.append("Architect did not finish")
        self.spec.set("cape_submission.validation_errors", problems, actor="controller")
        return not problems

    def _fix_wrong_package(self) -> bool:
        """Ask the Architect to pick a better package."""
        current = self.spec.get("cape_submission.package", "unknown")
        format_ = self.spec.get("sample.format",    "unknown")
        os_tgt  = self.spec.get("sample.os_target", "unknown")
        reason  = (
            f"WRONG_PACKAGE: package='{current}' produced no process data. "
            f"sample.format={format_}, sample.os_target={os_tgt}. "
            f"Re-select the correct CAPE package for this sample type."
        )
        adjusted = self._adjust_submission(reason)
        new_pkg = self.spec.get("cape_submission.package", current)
        problems = self.spec.get("cape_submission.validation_errors")
        ok = new_pkg != current and adjusted
        self._record_correction(F_WRONG_PACKAGE,
                                f"Architect.adjust → new package",
                                f"{current} → {new_pkg}; " + ("validated for retry" if ok else
                                "not recovered: " + "; ".join(problems or ["package unchanged or Architect incomplete"])))
        return ok

    def _fix_timeout_no_data(self) -> bool:
        """Increase the observation budget; use only implemented options."""
        current_timeout = self.spec.get("cape_submission.timeout") or 120
        new_timeout     = min(int(current_timeout) + 60, 300)
        current_options = self.spec.get("cape_submission.options") or ""
        caps = self.spec.get("cape_submission.backend_capabilities") or {}
        monitor_options = caps.get("cape_monitor_options", False) if caps else not is_qemu(self.cape_client)

        additions = []
        if monitor_options and "force-sleepskip" not in current_options:
            additions.append("force-sleepskip=1")
        if monitor_options and "human=1" not in current_options:
            additions.append("human=1")

        new_options = current_options
        if additions:
            new_options = current_options + "," + ",".join(additions)

        self.spec.set("cape_submission.timeout", new_timeout, actor="controller")
        self.spec.set("cape_submission.options", new_options, actor="controller")
        # Also disable memory dump to reduce processing time
        self.spec.set("cape_submission.memory", False, actor="controller")

        self._record_correction(
            F_TIMEOUT_NO_DATA,
            f"timeout {current_timeout}→{new_timeout}, options+={additions}",
            "parameters updated"
        )
        return True

    def _fix_submission_error(self) -> bool:
        """Ask Architect to diagnose and fix the submission command."""
        reason = (
            "SUBMISSION_ERROR: submission or sample startup failed. Inspect the "
            "recorded backend status and execution errors; check sample format, "
            "architecture, package, platform and available machines against the "
            "backend capabilities. Fix supported submission parameters, or record "
            "cape_submission.error if the failure cannot be resolved."
        )
        ok = self._adjust_submission(reason)
        problems = self.spec.get("cape_submission.validation_errors")
        self._record_correction(F_SUBMISSION_ERROR,
                                "Architect.adjust for submission error",
                                "configuration validated for retry" if ok else
                                "configuration still invalid: " + "; ".join(problems or ["Architect did not finish"]))
        return ok

    def _fix_report_missing(self) -> bool:
        """Wait longer for CAPE to finish processing."""
        if is_qemu(self.cape_client):
            # submit_file is synchronous: there is no background CAPE processor
            # or legacy storage path that could finish this report later.
            self._record_correction(
                F_REPORT_MISSING, "check synchronous QEMU result",
                "report unavailable; no background processor to recover it",
            )
            return False
        self.log.info("Executor", "Fix: waiting for CAPE to finish processing...")
        time.sleep(60)
        task_id = self._current_task_id()
        if not task_id:
            return False
        ok = self.host_ops.report_exists(task_id, self.cape_client.cfg.storage)
        self._record_correction(F_REPORT_MISSING,
                                "wait 60s for processing",
                                "report found" if ok else "still missing")
        return ok

    # ── Correction loop ───────────────────────────────────────────────────────

    def _attempt_correction(self) -> bool:
        """
        Diagnose the current failure and attempt to fix it.
        Returns True if the fix was applied (not necessarily successful).
        Returns False if the retry budget for this failure type is exhausted.
        """
        failure_type = self._diagnose_failure()

        count = self._correction_counts.get(failure_type, 0)
        if count >= MAX_CORRECTIONS_PER_TYPE:
            self.log.warning(
                "Executor",
                f"Correction budget exhausted for {failure_type} "
                f"(attempted {count}× already). Giving up on this failure type."
            )
            return False

        self._correction_counts[failure_type] = count + 1
        self.log.info("Executor",
                      f"Applying correction for {failure_type} "
                      f"(attempt {count + 1}/{MAX_CORRECTIONS_PER_TYPE})")

        fix_map = {
            F_VM_DOWN:           self._fix_vm_down,
            F_CAPE_SERVICE_DOWN: self._fix_cape_service_down,
            F_AGENT_UNREACHABLE: self._fix_agent_unreachable,
            F_WRONG_PACKAGE:     self._fix_wrong_package,
            F_TIMEOUT_NO_DATA:   self._fix_timeout_no_data,
            F_SUBMISSION_ERROR:  self._fix_submission_error,
            F_REPORT_MISSING:    self._fix_report_missing,
            F_UNKNOWN:           lambda: False,
        }

        fix_fn = fix_map.get(failure_type, lambda: False)
        try:
            return fix_fn()
        except (LedgerError, HostOpError) as e:
            # A refused host operation (no lease, unknown VM, foreign task)
            # is a failed correction, not a reason to abort the whole run
            # with an unhandled exception three frames up.
            self._record_correction(failure_type, "host operation refused", str(e))
            return False

    # ── Agent loop runner ─────────────────────────────────────────────────────

    def _run_agent_loop(self, initial_message: str,
                        max_iterations: int = 60) -> dict:
        # Pin the facts that matter most for correct report retrieval so
        # they can't be lost to context trimming mid-run: which sample this
        # is (sha256) and where it lives. The task_id itself is discovered
        # during the run, not pinned here — see _persist_report_authoritatively,
        # which is the harness-side (non-LLM) source of truth for the final
        # report artefact regardless of what the agent believes mid-run.
        if self.ctx.has_sample:
            pinned = {
                "sample.sha256": self.ctx.sample.sha256,
                "sample.path":   str(self.ctx.sample.path),
            }
        else:
            pinned = {
                "sample.sha256": self.spec.get("sample.sha256", "unknown"),
                "sample.path":   self.spec.get("sample.path", "unknown"),
            }
        loop = AgentLoop(
            llm            = self.llm,
            system_prompt  = SYSTEM_PROMPT,
            spec           = self.spec,
            log            = self.log,
            agent_name     = "Executor",
            max_iterations = max_iterations,
            pinned_facts   = pinned,
            cape_client    = self.cape_client,
            ctx            = self.ctx,
        )
        return loop.run(initial_message)

    def _validate(self) -> bool:
        """
        True once this run has at least one CAPE task in the ledger.

        Used to read `cape_submission.pass*_task_id` and
        `executor.passes_completed` from the spec — fields a model could
        write in the old design, and that nothing wrote once they became
        controller-owned. The ledger is populated by the cape_submit tool
        from the receipt CAPE returned, so this is the same fact the host
        operations authorise against.
        """
        return self.ctx.latest_task() is not None

    # ── Authoritative report retrieval (harness-side, not LLM-driven) ──────────
    #
    # Previously the Executor agent itself would `docker exec cat ... > file`
    # the report via a truncated shell tool, and _validate() only checked
    # that *a* task_id existed — not that the report belonged to this sample
    # or contained any actual behavioral data. That let empty/evaded/
    # cross-contaminated reports pass as "valid" and left the Analyst stage
    # to rediscover (or fail to discover) the real report from scratch.
    # This method fetches the report directly via CAPEClient (which itself
    # tries several storage-path fallbacks — see cape_client.py) and writes
    # a verified, complete copy to the workspace as the single source of
    # truth for the Analyst stage.

    def _persist_report_authoritatively(self, task_id) -> dict:
        """
        Fetch the report for task_id via CAPEClient, verify its target
        sha256 matches the submitted sample, write the full JSON to the
        workspace, and record verification + content-quality flags in the
        spec. Returns the quality dict (see CAPEClient.report_has_signal).
        """
        sample_sha256 = (self.ctx.sample.sha256 if self.ctx.has_sample
                         else self.spec.get("sample.sha256", ""))
        try:
            task_id = self.ctx.require_task(int(task_id)).task_id
            report, verified, report_sha256 = self.cape_client.get_report_verified(
                task_id, expected_sha256=sample_sha256
            )
        except Exception as e:
            self.log.warning("Executor",
                             f"Could not fetch authoritative report for task {task_id}: {e}")
            self.spec.set("executor.report_sha256_verified", False, actor="controller")
            self.spec.set("executor.report_fetch_error", str(e), actor="controller")
            return {"has_signal": False, "verified": False, "error": str(e)}

        out_path = self.workspace / f"cape_report_{task_id}.json"
        try:
            # 0600 and atomic: this file is what the Analyst reads, and the
            # model's own cape_fetch_report may have saved a copy under the
            # same name — the harness copy must be the one that lands last.
            tmp = out_path.with_name(f".{out_path.name}.tmp{os.getpid()}")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(report, f)
            os.replace(tmp, out_path)
            # SG-INT-02: the ledger keeps the digest of what was written and
            # whether the analysis target matched; verified_report() only
            # ever returns a matching one.
            self.ctx.record_report(task_id, out_path, target_sha256_matches=bool(verified))
        except Exception as e:
            self.log.warning("Executor", f"Could not persist {out_path}: {e}")

        self.spec.set("executor.report_sha256_verified", verified, actor="controller")
        self.spec.set("executor.report_sha256_seen", report_sha256, actor="controller")

        if not verified:
            # INT-04 fix: a sha256 mismatch is a hard failure, not a
            # warning-and-proceed. The mismatched report is quarantined
            # under a separate spec key and never written to
            # pass2.artefacts.cape_report — the Analyst stage only ever
            # reads the authoritative key, so it can no longer be handed a
            # stale/cross-run report as if it were ground truth.
            self.log.warning(
                "Executor",
                f"Report task_id={task_id} sha256={report_sha256!r} does NOT match "
                f"sample sha256={sample_sha256!r} — likely stale/cross-run report. "
                f"Quarantining rather than presenting it as authoritative."
            )
            self.spec.set("pass2.artefacts.quarantined_report", str(out_path), actor="controller")
            self.spec.set("pass2.artefacts.quarantined_report_task_id", int(task_id), actor="controller")
            quality = self.cape_client.report_has_signal(report)
            quality["verified"] = False
            self.spec.set("executor.report_quality", quality, actor="controller")
            return quality

        self.spec.set("pass2.artefacts.cape_report", str(out_path), actor="controller")
        self.spec.set("pass2.artefacts.cape_report_task_id", int(task_id), actor="controller")

        quality = self.cape_client.report_has_signal(report)
        quality["verified"] = True
        self.spec.set("executor.report_quality", quality, actor="controller")
        if not quality["has_signal"]:
            self.log.warning(
                "Executor",
                f"CAPE report for task {task_id} has no behavioral signal "
                f"(processes={quality['process_count']}, signatures={quality['signature_count']}, "
                f"malscore={quality['malscore']}, network_events={quality['network_events']}). "
                f"Sample may have evaded detonation, or routing/package hooking failed."
            )
        return quality

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self):
        """
        Drive the CAPE submission. Holds the analysis VM lease for the whole
        stage (SG-CONC-01) and releases it on every exit path.
        """
        if is_qemu(self.cape_client):
            # Each task owns a disposable guest/overlay. A lease on the legacy
            # cuckoo1/cuckoo2_linux VM would describe the wrong resource.
            return self._run()
        vm = self._vm_for_platform()
        self.ctx.acquire_vm_lease(vm, VM_LEASE_TTL_SECONDS)
        self.log.info("Executor", f"VM lease acquired: {vm}")
        try:
            return self._run()
        finally:
            self.ctx.release_vm_lease()

    def _run(self):
        run_dir = self.workspace
        self.spec.set("executor.run_dir", str(run_dir), actor="controller")
        self.spec.set("executor.corrections", [], actor="controller")

        if not self.ctx.has_sample:
            self.spec.set("executor.validation_failed", True, actor="controller")
            self.spec.set("executor.validation_error",
                          "No sample bound to this run — nothing to submit",
                          actor="controller")
            self.log.error("Executor", "No sample bound to this run; refusing to submit")
            return {"passes_completed": 0}

        sample_path = str(self.ctx.sample.path)
        package     = self.spec.get("cape_submission.package", "exe")
        os_target   = self.spec.get("sample.os_target",   "unknown")

        self.log.info("Executor",
                      f"Starting CAPEv2 analysis. "
                      f"sample={sample_path} package={package} os={os_target}")

        initial = f"""Execute the malware analysis via CAPEv2.

Workspace:      {self.workspace}
Spec path:      {self.workspace / 'environment_spec.json'}
Sample path:    {sample_path}
Package:        {package}
OS target:      {os_target}
Max passes:     {self.max_passes}
Backend:        {(self.spec.get('cape_submission.backend_capabilities') or {}).get('backend', 'CAPEv2')}

The configured backend is reachable via the typed cape_* tools — start by
reading the full spec to get all submission parameters, then check backend
readiness (cape_service_check), then submit Pass 1 (cape_submit, 60s timeout),
assess results, then submit Pass 2 (full timeout), retrieve all artefacts
and write them to the spec.

Use cape_submit/cape_status/cape_fetch_report for every CAPE/Docker
interaction (P0-1/P0-2) — there is no general-purpose shell to fall back on.
{self.failure_context}
"""

        # ── First run ─────────────────────────────────────────────────────────
        self._run_agent_loop(initial, max_iterations=60)

        # ── Check for Pass 1 adjustment request ───────────────────────────────
        adjustment = self.spec.get("pass1.adjustment_needed")
        if adjustment:
            self.log.info("Executor",
                          f"Pass 1 adjustment requested: {adjustment}")
            if not self._adjust_submission(adjustment):
                self.spec.set("executor.validation_failed", True, actor="controller")
                self.spec.set("executor.validation_error",
                              "Architect adjustment is invalid: " + "; ".join(
                                  self.spec.get("cape_submission.validation_errors")), actor="controller")
                return {"passes_completed": len(self.ctx.tasks)}
            initial2 = f"""The previous submission needed adjustment.
The Architect has updated the cape_submission.* parameters.

Re-read the spec and run Pass 2 with the updated parameters.
Workspace: {self.workspace}
Spec path: {self.workspace / 'environment_spec.json'}
"""
            self._run_agent_loop(initial2, max_iterations=40)

        # ── Self-correction loop ───────────────────────────────────────────────
        correction_round = 0
        max_correction_rounds = 5

        while not self._validate() and correction_round < max_correction_rounds:
            correction_round += 1
            self.log.info("Executor",
                          f"Validation failed — correction round "
                          f"{correction_round}/{max_correction_rounds}")

            fixed = self._attempt_correction()
            if not fixed:
                self.log.warning("Executor",
                                 "Correction returned False — stopping correction loop")
                break

            # Re-run the agent after applying the fix
            retry_msg = f"""A failure was detected and a correction was applied.

Apply the recorded correction and re-attempt the analysis:
  - Re-read the spec for updated submission parameters
  - Check readiness using the configured backend's tools
  - Re-submit the sample (Pass 1 then Pass 2)
  - Retrieve report and artefacts
  - Write results to spec

Workspace: {self.workspace}
Spec path: {self.workspace / 'environment_spec.json'}
Correction applied: {json.dumps(self.spec.get('executor.corrections', [])[-1], indent=2)}
"""
            self._run_agent_loop(retry_msg, max_iterations=50)

        # ── Final validation ───────────────────────────────────────────────────
        if not self._validate():
            self.log.warning("Executor",
                             "VALIDATION FAILED after all correction attempts. "
                             "Removing stale cape_report files.")
            for f in glob.glob(str(self.workspace / "cape_report*.json")):
                os.remove(f)
                self.log.warning("Executor", f"Removed stale report: {f}")
            self.spec.set("executor.validation_failed", True, actor="controller")
            self.spec.set("executor.validation_error",
                          "No confirmed CAPE task ID after self-correction",
                          actor="controller")
            passes = len(self.ctx.tasks)
            self.log.info("Executor",
                          f"CAPEv2 analysis finished. Passes completed: {passes}")
            return {"passes_completed": passes}

        task_id = self._current_task_id()
        passes  = len(self.ctx.tasks)
        self.log.info("Executor",
                      f"VALIDATION PASSED: task_id={task_id}, passes={passes}, "
                      f"corrections={correction_round}")

        # ── Authoritative report fetch + content-quality / provenance check ────
        # Bypasses the LLM's truncated shell tool entirely for the artefact
        # that matters most, and surfaces (rather than silently accepting)
        # empty or mismatched-sample reports.
        quality = self._persist_report_authoritatively(task_id)

        if quality.get("execution_valid") is False:
            # A failed launcher/collector is not evasion. Preserve diagnostic
            # artefacts, but never let a timeout signature certify this run.
            self.spec.set("executor.validation_failed", True, actor="controller")
            self.spec.set("executor.validation_error",
                          "Sample execution was not verified; inspect sandboxgen execution_errors "
                          "and launch_error in the saved report", actor="controller")
            return {"passes_completed": passes}

        # Either no behavioral signal at all, or (INT-04) a sha256
        # provenance mismatch — both used to pass through unnoticed. Give
        # it exactly one bounded retry with relaxed timing/human-simulation
        # options before accepting it as a (documented) genuine
        # evasion/empty result, or as a hard failure, rather than a bug.
        needs_retry = not quality.get("has_signal", False) or not quality.get("verified", False)
        if needs_retry and not self.spec.get("executor.empty_data_retry_done"):
            self.spec.set("executor.empty_data_retry_done", True, actor="controller")
            self.log.warning(
                "Executor",
                "CAPE report has no behavioral signal or failed sha256 "
                "verification — retrying once with a larger timeout and "
                "only backend-supported options."
            )
            self._fix_timeout_no_data()
            retry_msg = f"""The previous CAPE run produced a report with no behavioral
signal (0 processes, 0 signatures, malscore 0), or the report's sha256 did not
match the submitted sample. Inspect executor.corrections for the actual
parameter changes. Re-submit Pass 2 with the updated
cape_submission.* parameters from the spec and retrieve the new report.
The new task_id is recorded by the harness automatically; do not try to
write task IDs or report paths to the spec.

Workspace: {self.workspace}
Spec path: {self.workspace / 'environment_spec.json'}
"""
            tasks_before = len(self.ctx.tasks)
            self._run_agent_loop(retry_msg, max_iterations=40)

            if len(self.ctx.tasks) > tasks_before:
                retry_task_id = self._current_task_id()
                quality = self._persist_report_authoritatively(retry_task_id)
                task_id = retry_task_id

        if quality.get("execution_valid") is False:
            self.spec.set("executor.validation_failed", True, actor="controller")
            self.spec.set("executor.validation_error", "Retry did not verify sample execution", actor="controller")
            return {"passes_completed": len(self.ctx.tasks)}

        if not quality.get("verified", False):
            # INT-04: a hash mismatch is a hard failure, never silently
            # accepted as the sample's report. The Analyst stage will find
            # no pass2.artefacts.cape_report key set and must not proceed
            # as if analysis succeeded.
            self.log.warning(
                "Executor",
                f"Final report for task_id={task_id} failed sha256 provenance "
                f"verification after retry — refusing to hand it to Analyst "
                f"as authoritative."
            )
            self.spec.set("executor.validation_failed", True, actor="controller")
            self.spec.set("executor.validation_error",
                          "CAPE report sha256 did not match submitted sample "
                          "after retry — see pass2.artefacts.quarantined_report",
                          actor="controller")
            passes = len(self.ctx.tasks)
            return {"passes_completed": passes}

        self.spec.set("executor.final_task_id", task_id, actor="controller")

        passes = len(self.ctx.tasks)
        self.log.info("Executor",
                      f"CAPEv2 analysis finished. Passes completed: {passes}. "
                      f"Report quality: {quality}")
        return {"passes_completed": passes}
