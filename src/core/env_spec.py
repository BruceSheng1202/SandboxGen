#!/usr/bin/env python3
"""
core/env_spec.py — Environment Specification

The central shared document that all agents read and write.
The Scout Agent creates and populates it.
Every subsequent agent reads it and adds their findings.

Structure mirrors what a human analyst would write when
planning a malware analysis environment.

Cross-platform fields added:
  sample.os_target      — windows / linux / macos / android / unknown
  sample.format         — PE / ELF / Mach-O / APK / script / archive / unknown
  sandbox.actual.access_method — ssh / winrm / docker_exec / adb / nspawn
  sandbox.actual.access — platform-specific connection details dict
"""

import json
import os
import time
from pathlib import Path

from core.spec_policy import (  # noqa: F401  (re-exported for callers)
    SpecPermissionError,
    SpecSchemaError,
    check_write,
    writable_paths_for,
)


class EnvironmentSpec:
    """
    Shared specification document. Supports dot-notation get/set.
    Every write is immediately persisted to disk so agents can
    inspect it at any point.
    """

    def __init__(self, workspace: Path, run_id: str):
        self.workspace  = workspace
        self.run_id     = run_id
        self._spec_path = workspace / "environment_spec.json"
        self._data      = self._initial_structure(run_id)
        self._writes: list[dict] = []
        self.save(self._spec_path)

    # ------------------------------------------------------------------

    def _initial_structure(self, run_id: str) -> dict:
        return {
            "run_id":     run_id,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),

            # ── Sample ────────────────────────────────────────────────
            # Populated by Scout. All subsequent agents read from here.
            "sample": {
                "path":         None,   # absolute path to binary/repo on host
                "source":       None,   # "binary" | "repo"
                "repo_url":     None,
                "sha256":       None,
                "file_type":    None,   # raw output of `file` command
                "size_bytes":   None,

                # Cross-platform identity fields (NEW)
                "format":       None,   # PE | ELF | Mach-O | APK | script |
                                        # archive | unknown
                "os_target":    None,   # windows | linux | macos | android |
                                        # cross-platform | unknown
                "architecture": None,   # x86_64 | i386 | arm64 | arm | mips | …
                "packed":       False,
                "interpreter":  None,   # for scripts: python3 | node | bash |
                                        # powershell | …
            },

            # ── Classification ────────────────────────────────────────
            "classification": {
                "type":       None,   # ransomware | rat | cryptominer |
                                      # rootkit | dropper | worm | spyware |
                                      # unknown
                "confidence": None,   # high | medium | low
                "family":     None,
                "basis":      [],     # list of signal strings
            },

            # ── Sandbox ───────────────────────────────────────────────
            # What the Scout recommends; Architect fills in "actual".
            "sandbox": {
                "isolation":  None,   # qemu | docker | nspawn | avd |
                                      # qemu-windows | qemu-macos | wine
                "os":         None,   # ubuntu-22.04 | windows-10 |
                                      # macos-14 | android-33 | …
                "arch":       None,
                "ram_mb":     None,
                "disk_gb":    None,
                "reasoning":  None,

                # Filled in by Architect after build
                "actual": {
                    "isolation":      None,
                    "reasoning":      None,
                    "deviations":     None,

                    # Cross-platform access abstraction (NEW)
                    # access_method drives how Executor connects & monitors
                    "access_method":  None,   # ssh | winrm | docker_exec |
                                              #  adb | nspawn
                    # access holds all connection details for that method:
                    #
                    #   ssh:
                    #     { "host": "127.0.0.1", "port": 2222,
                    #       "user": "analyst", "key_path": "/path/to/key" }
                    #
                    #   winrm:
                    #     { "host": "127.0.0.1", "port": 5985,
                    #       "user": "analyst", "password": "…",
                    #       "transport": "ntlm" }
                    #
                    #   docker_exec:
                    #     { "container": "amsa_sandbox_<run_id>" }
                    #
                    #   adb:
                    #     { "serial": "emulator-5554" }
                    #
                    #   nspawn:
                    #     { "machine": "amsa-<run_id>",
                    #       "root": "/var/lib/machines/amsa-<run_id>" }
                    "access":         {},

                    # Platform-specific extras written by Architect
                    "vm_snapshot":    None,   # QEMU snapshot name if taken
                    "qemu_pid_file":  None,
                    "container_name": None,
                    "avd_name":       None,   # Android emulator AVD
                },
            },

            # ── Network ───────────────────────────────────────────────
            "network": {
                "mode":           None,   # fakenet | nat | isolated
                "intercept_dns":  False,
                "intercept_http": False,
                "c2_server":      None,
                "reasoning":      None,
            },

            # ── Guest environment ─────────────────────────────────────
            # What is set up *inside* the sandbox.
            "environment": {
                "os_version":        None,
                "user_profile":      None,   # office_worker | developer |
                                             # server | mobile_user
                "decoy_files":       {},
                "running_services":  [],
                "processes_to_fake": [],
                "anti_evasion":      {},

                # Platform-specific environment details (NEW)
                # Architect populates whichever applies.
                "windows": {
                    # Registry keys pre-populated for realism
                    "registry_keys":     [],
                    # Installed software visible to malware
                    "installed_software": [],
                    # Event log channels to enable
                    "event_log_channels": [],
                    # Sysmon config path inside guest
                    "sysmon_config":     None,
                },
                "android": {
                    "package_name":  None,   # if APK — the main package
                    "apk_path":      None,   # path inside emulator
                    "api_level":     None,
                },
            },

            # ── Monitors ─────────────────────────────────────────────
            # Keyed by monitor name → { "reasoning": …, "path": … }
            # Scout populates with recommendations.
            # Executor updates with actual artefact paths.
            #
            # Linux monitors:  strace | tcpdump | perf | fakenet | blktrace
            # Windows monitors: sysmon | procmon | etw | wireshark | fakenet
            # Android monitors: logcat | strace | tcpdump | frida
            # Common:           tcpdump | fakenet | strings_output
            "monitors": {},

            # ── Host (filled by Architect) ────────────────────────────
            "host": {},

            # ── Tools installed on host during this run ───────────────
            "tools_installed": [],

            # ── Execution passes ──────────────────────────────────────
            "pass1": {
                "completed":        False,
                "observations":     [],
                "duration_s":       None,
                "adjustment_needed": None,
                "hypothesis_confirmed": None,
            },
            "pass2": {
                "completed":  False,
                "artefacts":  {},   # monitor_name → absolute path on host
            },
            "passes":   [],   # list of {number, duration_s, artefacts}

            # ── Executor bookkeeping ───────────────────────────────────
            "executor": {
                "passes_completed": 0,
                "current_pass":     0,
                "run_dir":          None,
            },

            # ── Final report (written by Analyst) ─────────────────────
            "report": None,
        }

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get(self, key: str, default=None):
        """Dot-notation getter. e.g. get('classification.type')"""
        keys = key.split(".")
        val  = self._data
        for k in keys:
            if not isinstance(val, dict) or k not in val:
                return default
            val = val[k]
        return val

    def set(self, key: str, value, *, actor: str):
        """
        Dot-notation setter, authorised against `spec_policy`.

        SG-CTL-02: `actor` is mandatory and has no default. The old setter
        was reachable from the `update_spec` tool with no notion of who was
        writing, so an agent could set `sample.path` or a CAPE task ID and the
        harness would read it straight back as authorization. Requiring the
        caller to name itself means a new call site cannot quietly inherit
        controller privilege — it has to say `actor="controller"`, which is
        greppable and shows up in review.

        Raises SpecPermissionError for an unauthorised path and
        SpecSchemaError for a value that fails its type, enum or bounds.
        """
        check_write(key, value, actor)

        keys    = key.split(".")
        current = self._data
        for k in keys[:-1]:
            if k not in current or not isinstance(current[k], dict):
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
        self._writes.append(
            {"at": time.time(), "actor": actor, "key": key,
             "value_type": type(value).__name__}
        )
        self.save(self._spec_path)

    def update(self, key: str, data: dict, *, actor: str):
        """Merge dict into a nested key."""
        existing = self.get(key) or {}
        if isinstance(existing, dict) and isinstance(data, dict):
            merged = dict(existing)
            merged.update(data)
            self.set(key, merged, actor=actor)
        else:
            self.set(key, data, actor=actor)

    def append(self, key: str, value, *, actor: str):
        """
        Append to a list at key.

        Round-1 INT-11: the old version assumed the existing value was a list
        and would raise AttributeError deep in agent code if a previous write
        had made it a scalar. A non-list here is a policy failure, reported as
        one.
        """
        existing = self.get(key)
        if existing is None:
            existing = []
        if not isinstance(existing, list):
            raise SpecSchemaError(
                f"cannot append to {key}: current value is "
                f"{type(existing).__name__}, not a list"
            )
        self.set(key, [*existing, value], actor=actor)

    def write_log(self) -> list:
        """Who wrote what, in order — folded into the run manifest."""
        return list(self._writes)

    def raw(self) -> dict:
        return self._data

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Path):
        """
        INT-11 fix: write-then-rename instead of writing the target file
        in place. set() calls save() on every single write, so a crash or
        concurrent read mid-write used to be able to observe a truncated
        or half-written spec; os.replace() is atomic on the same
        filesystem, so readers only ever see a complete previous or new
        version, never a partial one.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.tmp{os.getpid()}")
        with open(tmp_path, "w") as f:
            json.dump(self._data, f, indent=2, default=str)
        os.replace(tmp_path, path)

    def load(self, path: Path):
        with open(path) as f:
            self._data = json.load(f)

    def to_json(self) -> str:
        return json.dumps(self._data, indent=2, default=str)
