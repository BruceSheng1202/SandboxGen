#!/usr/bin/env python3
"""
agents/architect.py — Architect Agent (CAPEv2 edition)

In the original AMSA, the Architect built a sandbox from scratch.
In this CAPEv2 edition, the Architect's job is:

  1. Read the Scout's Environment Spec (malware profile)
  2. Query CAPEv2 for available analysis VMs
  3. Select the optimal submission parameters:
       - analysis package  (exe, dll, doc, js, pdf, zip, …)
       - VM / machine label
       - platform tag
       - network mode     (internet, inetsim, none)
       - timeout
       - memory dump      (yes/no)
       - CAPE options     (sleep skipping, human simulation, …)
  4. Handle any missing prerequisites:
       - If no matching VM exists → log clearly and raise
       - If package type is unusual → determine correct package name
  5. Write the final submission parameters to the spec
     under cape_submission.*
  6. Provide an adjust() method for the Executor to call
     if execution fails and parameters need changing

The Architect does NOT build VMs or install software. The configured backend
provides its available guests and manages their lifecycle.
"""

import json
from pathlib import Path
from core.agent_loop import AgentLoop
from core.backend_contract import is_qemu
from core.cape_client import CAPEClient


SYSTEM_PROMPT = r"""
You are the Architect Agent in AMSA — an Agentic Malware Sandbox Analyser.

YOUR GOAL:
Read the Scout's malware profile from the Environment Spec and determine
the optimal CAPEv2 submission parameters to ensure the malware executes
and is analysed correctly.

Your job is to configure a submission to the deployed backend. Its capability
and machine lists determine what is available and how guests are managed.

YOUR FIRST ACTION IS ALWAYS TO READ THE SPEC.

BACKEND CAPABILITIES OVERRIDE THE CAPEv2 DEFAULTS BELOW:
If cape_submission.backend_capabilities is present, use that actual tool
contract. The qemu-tcg backend is NOT CAPEv2: it supports Linux ELF and scripts
(.sh/.py/.pl) on qemu-linux, and Windows exe/dll when qemu-windows is available.
The windows_packages field lists Windows packages, not all supported formats.
function= is its only implemented Windows option. Do not request or
claim CAPE sleep skipping, injection/extraction, or memory dumps on that backend.
For DLLs it uses rundll32: explicitly select a compatible exported entry, not
DllMain. No entry is guessed. A loaded DLL does not prove the chosen export
succeeded. The tool cannot provision VMs or install dependencies.

TOOL INTERFACE:
<tool_call>
{"tool": "analyze_sample", "operation": "identify", "path": "..."}
</tool_call>

<tool_call>
{"tool": "update_spec", "key": "cape_submission.package", "value": "exe"}
</tool_call>

Available tools: analyze_sample, read_spec, update_spec, append_spec,
                 read_file, write_file, query_json, cape_service_check,
                 log_decision, log_observation, finish

═══════════════════════════════════════════════════════════════════════
STEP 1 — READ SPEC AND UNDERSTAND THE SAMPLE
═══════════════════════════════════════════════════════════════════════

read_spec() and extract:
  sample.format        — PE | ELF | Mach-O | APK | script | archive | office
  sample.os_target     — windows | linux | macos | android
  sample.architecture  — x86_64 | i386 | arm64 | …
  sample.packed        — true/false
  sample.interpreter   — (scripts) python3 | powershell | node | …
  classification.type  — ransomware | rat | cryptominer | dropper | …
  network.mode         — fakenet | nat | isolated (Scout's recommendation)
  environment.anti_evasion — evasion techniques detected by Scout

═══════════════════════════════════════════════════════════════════════
STEP 2 — INSPECT AVAILABLE CAPE VMs
═══════════════════════════════════════════════════════════════════════

Available VMs are already pre-populated in the spec by the harness
(cape_submission.available_machines, via CAPEClient.list_machines()) — there
is no general-purpose shell (CTL-01), so do not try `docker exec cape ...`.
read_spec() to see them; if the list is empty,
{"tool": "cape_service_check"} to see whether CAPE/the VM is up at all.

For each available VM, note:
  - label (the name CAPE uses to refer to it)
  - platform (windows / linux)
  - arch (x86 / x64)
  - tags (win10, win7, etc.)

═══════════════════════════════════════════════════════════════════════
STEP 3 — SELECT ANALYSIS PACKAGE
═══════════════════════════════════════════════════════════════════════

The analysis package tells CAPEv2 HOW to execute the sample inside the VM.
Choose based on sample.format and sample.os_target:

  PE executable (.exe):        package = "exe"
  PE DLL (.dll):               package = "dll"
  PE .NET assembly:            package = "exe"  (or "comrat" if .NET RAT)
  PowerShell script (.ps1):    package = "ps1"
  JavaScript (.js):            package = "js"
  VBScript (.vbs):             package = "vbs"
  Office Word (.doc/.docx):    package = "doc"   (requires Office installed in VM)
  Office Excel (.xls/.xlsx):   package = "xls"
  Office macro-enabled:        package = "doc" or "xls"
  PDF:                         package = "pdf"
  ZIP/archive with EXE inside: package = "zip"
  AutoIT script (.au3):        package = "autoit"
  HTA file (.hta):             package = "hta"
  Batch file (.bat/.cmd):      package = "generic"
  Python script (.py):         package = "python"
  Linux shell/Perl script:     package = "generic" (QEMU .sh/.pl only)
  Linux ELF:                   package = "elf"   (needs Linux VM)
  Android APK:                 package = "apk"   (needs Android VM)

For qemu-tcg, Windows packages are exe/dll only. Other CAPEv2 packages above
require a backend that explicitly supports them. Do not use generic to bypass
an unsupported format or guest architecture.

Important DLL notes:
  - If sample is a DLL, check exports: analyze_sample(operation="pe_exports", path="{path}")
  - Select an explicit exported function or ordinal compatible with rundll32.
    Set options="function=<export or #ordinal>". DllMain is not a valid choice.

═══════════════════════════════════════════════════════════════════════
STEP 4 — SELECT SUBMISSION OPTIONS
═══════════════════════════════════════════════════════════════════════

Build the options string based on Scout's findings:

TIMEOUT:
  Default: 120 seconds
  Ransomware: 180 seconds (needs time to encrypt files)
  RAT/C2: 120 seconds (connects fast)
  Cryptominer: 60 seconds (behaviour clear quickly)
  Dropper: 90 seconds (download + execute)
  If sample.packed == true: add 30 seconds

MEMORY DUMP:
  Enable only when backend_capabilities implements memory dumps and
  Scout's evidence warrants them (e.g. suspected injection or rootkit).
  Otherwise: memory = false. Do not request an unimplemented channel.

NETWORK MODE:
  Use the controller's recorded route and backend_capabilities as the
  actual network policy. A legacy network.mode label or network= option
  does not prove internet access or a working simulator. The harness
  enforces its route at submission; record any resulting observation limits.

SLEEP SKIPPING (only when the actual backend implements it):
  If the backend supports it and the sample has sleep-based evasion: options += ",force-sleepskip=1"
  This patches Sleep() calls in the monitor to skip long delays

HUMAN SIMULATION (only when the actual backend implements it):
  For supported backends and samples that check for user interaction:
  options += ",human=1"
  This simulates mouse movement and clicks in the VM

CAPE EXTRACTION OPTIONS (not implemented by qemu-tcg):
  Enable only if backend_capabilities explicitly supports these features:
  options += ",combo=1"      # enables compression+injection+extraction
  options += ",extraction=1" # extract payloads from processes
  options += ",injection=1"  # capture injected payloads

═══════════════════════════════════════════════════════════════════════
STEP 5 — SELECT VM
═══════════════════════════════════════════════════════════════════════

Match the sample's requirements to available VMs:

  Windows PE (x86):   need platform=windows, arch=x86 or x86_64 VM
  Windows PE (x64):   need platform=windows, arch=x86_64 VM
  Linux ELF:          need platform=linux VM (if available)
  Script:             match by OS target

Select a VM only when its OS and supported architectures match the sample.
A single available VM must still be compatible. The x86_64 QEMU Linux guest
supports i386/x86_64 ELF; it does not execute ARM ELF or supply Android's ABI.

If NO matching VM is available:
  - Log the mismatch clearly
  - Set cape_submission.error to explain why
  - Do NOT proceed with wrong VM
  - If a previous mismatch is resolved, clear cape_submission.error with null.
    A nonempty error or incomplete/incompatible plan fails stage validation.

═══════════════════════════════════════════════════════════════════════
STEP 6 — WRITE SUBMISSION PARAMETERS TO SPEC
═══════════════════════════════════════════════════════════════════════

Write all selected parameters:

  update_spec("cape_submission.package",          "<package>")
  update_spec("cape_submission.machine",          "<vm_label or null>")
  update_spec("cape_submission.platform",         "<windows|linux|android>")
  update_spec("cape_submission.timeout",          <seconds>)
  update_spec("cape_submission.memory",           <true|false>)
  update_spec("cape_submission.enforce_timeout",  <true|false>)
  update_spec("cape_submission.options",          "<cape options string>")
  update_spec("cape_submission.tags",             "<comma-separated tags or null>")
  update_spec("cape_submission.priority",         1)
  update_spec("cape_submission.reasoning",        "<why these parameters were chosen>")

  (cape_submission.available_machines is pre-filled by the harness from
   CAPE's machine list — read it, do not write it.)

═══════════════════════════════════════════════════════════════════════
STEP 7 — VERIFY SAMPLE PATH IS ACCESSIBLE
═══════════════════════════════════════════════════════════════════════

The Executor will submit sample.path to CAPEv2.
Verify the file exists and is readable:

  analyze_sample(operation="identify", path="{sample.path}")
  analyze_sample(operation="file", path="{sample.path}")

Submission goes through cape_submit, which handles the configured backend's
staging/upload. Do not translate host/container paths or copy sample files.

═══════════════════════════════════════════════════════════════════════
STEP 8 — FINISH
═══════════════════════════════════════════════════════════════════════

  finish("CAPEv2 submission parameters configured. Package={pkg}. VM={vm}. Timeout={t}s. Options={opts}.")

IMPORTANT PRINCIPLES:
- READ THE SPEC FIRST — all sample info is there from the Scout
- Match package to format precisely — wrong package = no analysis data
- Enable only options implemented by the actual backend; qemu-tcg does not implement combo/extraction/injection/memory dumps.
- Log the reasoning for every decision — the Executor reads this
- If the pinned sample is not readable, record the error; do not change its path
- Never guess the package — use the format→package mapping above
"""


class ArchitectAgent:
    # P0-3 (audit INF-02): the LLM's network.mode vocabulary mapped to the
    # CAPE `network=` option value. Any mode not listed here — including a
    # missing network.mode — defaults to "none" (no egress). This map, not
    # the LLM's transcription of the options string, is authoritative.
    _NETWORK_MODE_TO_CAPE = {
        "isolated": "none",
        "fakenet":  "internet",
        "nat":      "internet",
        "internet": "internet",
    }

    def __init__(self, spec, log, llm, workspace: Path,
                 cape_client: CAPEClient = None, ctx=None,
                 failure_context: str = ""):
        self.spec        = spec
        self.log         = log
        self.llm         = llm
        self.workspace   = workspace
        self.cape_client = cape_client
        self.ctx         = ctx
        # Retry edition: a controller-rendered summary of earlier attempts
        # (see orchestrator._format_failure_context). Empty on a first or
        # single attempt.
        self.failure_context = failure_context or ""

    def _enforce_network_policy(self):
        """
        P0-3: never trust the LLM's transcription of the network=... token.
        Recompute it deterministically from network.mode and overwrite
        cape_submission.options, defaulting to network=none (default-deny)
        when network.mode is missing or unrecognized.
        """
        mode = self.spec.get("network.mode")
        cape_network = self._NETWORK_MODE_TO_CAPE.get(mode)
        if cape_network is None:
            cape_network = "none"
            self.log.warning(
                "Architect",
                f"network.mode={mode!r} missing/unrecognized — enforcing "
                f"network=none (default-deny, audit finding INF-02)."
            )

        options = self.spec.get("cape_submission.options", "") or ""
        parts = [p for p in options.split(",")
                 if p.strip() and not p.strip().startswith("network=")]
        if is_qemu(self.cape_client):
            # QEMU's isolated route is enforced by the submission controller;
            # it has no CAPE network= option or configurable simulator.
            cape_network = "none"
        else:
            parts.append(f"network={cape_network}")
        new_options = ",".join(parts)

        if new_options != options:
            self.log.info(
                "Architect",
                f"Enforced network policy: network.mode={mode!r} -> "
                f"network={cape_network!r} (options: {options!r} -> {new_options!r})"
            )
        self.spec.set("cape_submission.options", new_options, actor="controller")
        self.spec.set("cape_submission.network_mode_enforced", cape_network, actor="controller")
        return cape_network

    def run(self):
        self.log.info("Architect", "Configuring CAPEv2 submission parameters")

        # Pre-populate available machines from CAPEv2
        if self.cape_client:
            capabilities = getattr(self.cape_client, "capabilities", None)
            if callable(capabilities):
                self.spec.set("cape_submission.backend_capabilities", capabilities(), actor="controller")
            try:
                machines = self.cape_client.list_machines()
                self.spec.set("cape_submission.available_machines", machines, actor="controller")
                self.log.info("Architect",
                              f"Found {len(machines)} available VMs: "
                              f"{[m.get('name') for m in machines]}")
            except Exception as e:
                self.log.warning("Architect",
                                 f"Could not list CAPE machines: {e}")

        sample_path   = self.spec.get("sample.path",        "unknown")
        sample_format = self.spec.get("sample.format",      "unknown")
        os_target     = self.spec.get("sample.os_target",   "unknown")
        clf_type      = self.spec.get("classification.type","unknown")

        initial = f"""Configure CAPEv2 submission parameters for this malware sample.

Workspace:      {self.workspace}
Spec path:      {self.workspace / 'environment_spec.json'}
Sample path:    {sample_path}
Sample format:  {sample_format}
OS target:      {os_target}
Classification: {clf_type}

Select submission parameters supported by the deployed backend and its
available machines. Guest creation and lifecycle belong to the backend.

Start with read_spec, then read_spec(path="cape_submission") for actual
backend capabilities and available VMs. query_json can inspect a specific
field in environment_spec.json. Never repeatedly read a truncated prefix.
Write submission parameters that the actual backend supports.

CRITICAL: Verify sample.path exists on disk (analyze_sample "identify"/"file").
Submission goes through cape_submit, which handles staging/upload for the
configured backend; no model-driven Docker path check or copy step is needed.
{self.failure_context}
Call finish() when all cape_submission.* fields are written.
"""

        loop = AgentLoop(
            llm            = self.llm,
            system_prompt  = SYSTEM_PROMPT,
            spec           = self.spec,
            log            = self.log,
            agent_name     = "Architect",
            max_iterations = 30,
            cape_client    = self.cape_client,
            ctx            = self.ctx,
        )
        result = loop.run(initial)
        self._enforce_network_policy()
        self.log.info("Architect",
                      f"Configuration complete. iterations={result['iterations']}")
        return result

    def adjust(self, reason: str):
        """
        Called by Executor if analysis fails and parameters need adjustment.
        Re-runs the Architect with context about what went wrong.
        """
        self.log.info("Architect",
                      f"Adjustment requested: {reason}")

        initial = f"""The previous CAPEv2 submission failed or produced poor results.

Reason / adjustment needed:
  {reason}

Workspace:  {self.workspace}
Spec path:  {self.workspace / 'environment_spec.json'}

Read the current cape_submission.* fields from the spec,
understand what went wrong, and update the parameters to fix it.

Common adjustments:
  - Wrong package → update cape_submission.package
  - VM not found → check available_machines and pick correct one
  - Analysis timeout → increase cape_submission.timeout
  - No behaviour → inspect available evidence and backend capabilities; use only supported options. Missing observations alone do not prove evasion.
  - DLL entry point → add function=<export> to options
  (sample.path is controller-owned and cape_submit handles staging/upload —
   never try to move the file or rewrite its path.)

{self.failure_context}
Write the corrected parameters and call finish().
"""

        loop = AgentLoop(
            llm            = self.llm,
            system_prompt  = SYSTEM_PROMPT,
            spec           = self.spec,
            log            = self.log,
            agent_name     = "Architect",
            max_iterations = 20,
            cape_client    = self.cape_client,
            ctx            = self.ctx,
        )
        result = loop.run(initial)
        self._enforce_network_policy()
        self.log.info("Architect",
                      f"Adjustment complete. iterations={result['iterations']}")
        return result
