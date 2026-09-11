#!/usr/bin/env python3
"""
core/cape_client.py — CAPEv2 Client

Provides a unified interface to CAPEv2 via two modes:
  - local:  Direct Python API using CAPEv2's own database and storage
            (fastest, no auth needed, same machine)
  - rest:   HTTP REST API via /apiv2/ endpoints
            (works remotely, requires auth token)

Mode is selected via cape.yaml:
  mode: local          # or rest
  cape_root: /opt/CAPEv2   # for local mode
  url: http://localhost:8000  # for rest mode
  token: <api_token>          # for rest mode
  storage: /opt/CAPEv2/storage/analyses  # for report retrieval

The client exposes:
  submit_file(path, options)  → task_id
  get_task_status(task_id)    → status string
  get_report(task_id)         → dict (parsed report.json)
  list_machines()             → list of available VMs
  wait_for_completion(task_id, timeout, poll_interval) → final status
"""

import json
import logging
import re
import shlex
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("amsa")

# Safe-token validator for CAPE submit fields that get interpolated into a
# shell command string (machine/package/platform/tags). Anything not
# matching this is rejected outright rather than quoted-and-hoped — closes
# CTL-04 ("validate package, platform, machine through enums").
_SAFE_TOKEN = re.compile(r'^[A-Za-z0-9_.:,-]+$')


def _validate_token(name: str, value) -> str:
    value = str(value)
    if not _SAFE_TOKEN.match(value):
        raise ValueError(f"invalid characters in CAPE {name}={value!r} — refused")
    return value


def _require_ok(r, *, ok=(200,), context: str):
    """
    Raise a clear error for any response outside `ok` (audit INT-15: 401,
    403, or 500 responses — often HTML/JSON error bodies — must not be
    parsed as if they were a successful API result).
    """
    if r.status_code not in ok:
        raise RuntimeError(
            f"CAPE API error during {context}: HTTP {r.status_code} "
            f"from {r.url} — {r.text[:200]!r}"
        )


@dataclass
class CAPEConfig:
    mode:       str   = "local"          # local | rest
    cape_root:  str   = "/opt/CAPEv2"   # for local mode
    url:        str   = "http://localhost:8000"  # for rest mode
    token:      str   = ""              # for rest mode
    storage:    str   = "/opt/CAPEv2/storage/analyses"
    # Docker container name if CAPE runs in Docker
    # If set, commands are prefixed with docker exec
    container:  str   = "cape"
    timeout:    int   = 300             # max seconds to wait for analysis
    poll_interval: int = 15             # seconds between status polls
    # TLS verification for REST mode. Keep verification enabled; use
    # ca_bundle to trust a private CA. verify_ssl=False disables verification
    # when no CA bundle is supplied.
    verify_ssl: bool           = True
    ca_bundle:  Optional[str]  = None

    @classmethod
    def from_yaml(cls, path: str) -> "CAPEConfig":
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)
        cfg = cls()
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


class CAPEClient:
    """
    Unified CAPEv2 client.
    Supports local (direct file/DB access) and REST API modes.
    """

    def __init__(self, cfg: CAPEConfig, *, connect: bool = True):
        self.cfg = cfg
        self._session = None  # requests.Session for REST mode
        self._connected = False

        if cfg.mode not in ("rest", "local"):
            raise ValueError(f"Unknown CAPE mode: {cfg.mode}. Use 'local' or 'rest'.")
        if connect:
            self.connect()

    def connect(self) -> None:
        """
        Reach the CAPE deployment: build the REST session and probe
        `/apiv2/`, or check the local install root.

        Split out of the constructor so a pipeline object can be built —
        and tested — on a machine that is not a CAPE host; the orchestrator
        calls this before the first stage that needs CAPE.
        """
        if self._connected:
            return
        if self.cfg.mode == "rest":
            self._init_rest()
        else:
            self._verify_local()
        self._connected = True

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    # Hosts for which plaintext HTTP is tolerated (same-machine traffic never
    # leaves the loopback interface). Anything else over http:// leaks the
    # bearer token and report contents on the wire — audit finding INF-04.
    _LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

    def _warn_if_insecure_transport(self, url: str):
        parsed = urlsplit(url)
        if parsed.scheme == "http" and parsed.hostname not in self._LOCAL_HOSTS:
            logger.warning(
                "[CAPEClient] SECURITY: %s uses plaintext HTTP to a non-local "
                "host — the API token and every report transit in cleartext "
                "(audit finding INF-04). Use https:// (set verify_ssl/"
                "ca_bundle in cape.yaml for a self-signed cert) for any "
                "cross-host deployment.", url,
            )

    def _init_rest(self):
        self._warn_if_insecure_transport(self.cfg.url)
        try:
            import requests
            self._session = requests.Session()
            self._session.verify = self.cfg.ca_bundle or self.cfg.verify_ssl
            if self.cfg.token:
                self._session.headers["Authorization"] = f"Token {self.cfg.token}"
            # Verify connectivity
            r = self._session.get(f"{self.cfg.url}/apiv2/", timeout=10)
            _require_ok(r, context="connectivity check")
            logger.info("[CAPEClient] REST API reachable at %s (status %d)",
                        self.cfg.url, r.status_code)
        except Exception as e:
            raise RuntimeError(f"CAPEv2 REST API not reachable at {self.cfg.url}: {e}")

    def _verify_local(self):
        cape_root = Path(self.cfg.cape_root)
        if not cape_root.exists():
            raise RuntimeError(
                f"CAPEv2 root not found at {cape_root}. "
                f"Set cape_root in cape.yaml or switch to mode: rest."
            )
        logger.info("[CAPEClient] Local mode. CAPE root: %s", cape_root)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit_file(self, sample_path: str, options: dict = None) -> int:
        """
        Submit a file for analysis. Returns the task ID.

        options dict supports:
          machine     — specific VM label (e.g. 'cuckoo1')
          package     — analysis package (e.g. 'exe', 'dll', 'doc', 'js')
          platform    — 'windows' | 'linux'
          timeout     — analysis timeout in seconds
          memory      — bool, enable full memory dump
          enforce_timeout — bool
          tags        — comma-separated VM tags
          options     — CAPE options string (e.g. 'free=1,human=1')
          priority    — int (1=normal, 2=high)
          clock       — fake clock string '%m-%d-%Y %H:%M:%S'
        """
        options = options or {}
        logger.info("[CAPEClient] Submitting %s (options=%s)", sample_path, options)

        if self.cfg.mode == "rest":
            return self._submit_rest(sample_path, options)
        else:
            return self._submit_local(sample_path, options)

    def get_task_status(self, task_id: int) -> str:
        """
        Returns the task status string:
          pending | running | completed | reported |
          failed_analysis | failed_processing | failed_reporting
        """
        if self.cfg.mode == "rest":
            return self._status_rest(task_id)
        else:
            return self._status_local(task_id)

    # Known-good storage roots observed across benchmark runs — the CAPEv2
    # container's actual storage path has been inconsistent (varies by
    # deployment/mount setup), so a single hardcoded path is not reliable.
    # cfg.storage is always tried first; these are additional fallbacks.
    _STORAGE_ROOT_CANDIDATES = (
        "/opt/CAPEv2/storage/analyses",
        "/work/storage/analyses",
        "/home/cape/opt/CAPEv2/storage/analyses",
    )

    def get_report(self, task_id: int) -> dict:
        """
        Returns the parsed report.json for a completed task.
        Works by reading the JSON file directly from storage
        (same approach works for both local and REST modes since
        they share the same filesystem in our setup).
        """
        report_path = Path(self.cfg.storage) / str(task_id) / "reports" / "report.json"

        # Try direct file access first (works for both local and
        # containerized REST since storage is mounted)
        if report_path.exists():
            with open(report_path) as f:
                return json.load(f)

        # Fall back to REST API if file not directly accessible
        if self.cfg.mode == "rest" and self._session:
            try:
                return self._report_rest(task_id)
            except Exception:
                pass

        # Try via docker exec if container is configured — across several
        # storage root candidates, since the container's real layout has
        # been observed to differ from cfg.storage.
        if self.cfg.container:
            return self._report_via_docker(task_id)

        raise FileNotFoundError(
            f"Report not found for task {task_id} at {report_path}"
        )

    def get_report_verified(self, task_id: int, expected_sha256: str = None) -> dict:
        """
        Like get_report(), but also checks the report's own target sha256
        against expected_sha256 (the sample this AMSA run submitted).

        CAPE task IDs are a single global counter shared across every
        sample in a benchmark session, so a stale/leftover local report
        file — or a task ID collision after a fresh CAPE DB — can silently
        hand a completely unrelated sample's report to this run. Returns
        (report, verified: bool, report_sha256: str|None).
        """
        report = self.get_report(task_id)
        report_sha256 = (
            report.get("target", {}).get("file", {}).get("sha256")
            or report.get("target", {}).get("sha256")
        )
        verified = bool(expected_sha256) and bool(report_sha256) and \
            expected_sha256.strip().lower() == str(report_sha256).strip().lower()
        return report, verified, report_sha256

    @staticmethod
    def report_has_signal(report: dict) -> dict:
        """
        Checks whether a CAPE report actually contains dynamic behavioral
        data, rather than just existing. Executor's previous validation
        only checked that *a* task_id was assigned, which let runs with
        network=isolated, broken package hooking, or evaded detonation
        pass through indistinguishable from a genuine successful run.
        Returns a small dict of counts plus a "has_signal" verdict.
        """
        behavior   = report.get("behavior", {}) or {}
        processes  = behavior.get("processes", []) or []
        signatures = report.get("signatures", []) or []
        network    = report.get("network", {}) or {}
        malscore   = (report.get("malscore")
                      or report.get("info", {}).get("score")
                      or 0)
        try:
            malscore = float(malscore)
        except (TypeError, ValueError):
            malscore = 0.0

        network_hits = sum(len(network.get(k, []) or [])
                            for k in ("dns", "tcp", "http", "hosts"))

        has_signal = bool(processes) or bool(signatures) or malscore > 0 or network_hits > 0

        return {
            "process_count":   len(processes),
            "signature_count": len(signatures),
            "malscore":        malscore,
            "network_events":  network_hits,
            "has_signal":      has_signal,
        }

    def get_task_route(self, task_id: int) -> Optional[str]:
        """
        The network route CAPE recorded for a task, read back from the task
        record — or None when it cannot be read.

        SG-NET-01: a declared policy is worth nothing until the sandbox
        confirms it. The caller compares this against the route it asked for
        and treats None or a mismatch as a failed submission, never as "fine".
        Only REST exposes the task record; local mode returns None.
        """
        if self.cfg.mode != "rest":
            return None
        url = f"{self.cfg.url}/apiv2/tasks/view/{int(task_id)}/"
        r = self._require_session().get(url, timeout=10)
        _require_ok(r, context=f"route read-back for task {task_id}")
        data = r.json().get("data", {}) or {}
        route = data.get("route")
        if route is None:
            # Some builds nest task options; look one level down.
            opts = data.get("options")
            if isinstance(opts, dict):
                route = opts.get("route")
        return str(route) if route else None

    def supported_routes(self) -> set:
        # A real CAPEv2 deployment can route through its configured options.
        return {"drop", "none", "internet", "inetsim", "tor", "vpn"}

    def list_machines(self) -> list:
        """
        Returns list of available analysis VMs.
        Each entry: {'name': str, 'label': str, 'platform': str,
                     'tags': list, 'status': str}
        """
        if self.cfg.mode == "rest":
            return self._machines_rest()
        else:
            return self._machines_local()

    def wait_for_completion(self, task_id: int,
                            timeout: int = None,
                            poll_interval: int = None) -> str:
        """
        Polls until task reaches a terminal state.
        Returns the final status string.
        Raises TimeoutError if timeout is exceeded.
        """
        timeout       = timeout       or self.cfg.timeout
        poll_interval = poll_interval or self.cfg.poll_interval
        deadline      = time.time() + timeout
        last_status   = None

        logger.info("[CAPEClient] Waiting for task %d (timeout=%ds)", task_id, timeout)

        while time.time() < deadline:
            status = self.get_task_status(task_id)
            if status != last_status:
                logger.info("[CAPEClient] Task %d status: %s", task_id, status)
                last_status = status

            # Terminal states
            if status in ("reported", "failed_analysis",
                          "failed_processing", "failed_reporting"):
                return status

            time.sleep(poll_interval)

        raise TimeoutError(
            f"Task {task_id} did not complete within {timeout}s "
            f"(last status: {last_status})"
        )

    # ------------------------------------------------------------------
    # REST mode implementation
    # ------------------------------------------------------------------

    def _require_session(self):
        if self._session is None:
            self.connect()
        return self._session

    def _submit_rest(self, sample_path: str, options: dict) -> int:
        self._require_session()
        url  = f"{self.cfg.url}/apiv2/tasks/create/file/"
        data = {}

        # Map options to CAPE API fields
        field_map = {
            "machine":          "machine",
            "package":          "package",
            "platform":         "platform",
            "timeout":          "timeout",
            "memory":           "memory",
            "enforce_timeout":  "enforce_timeout",
            "tags":             "tags",
            "options":          "options",
            "priority":         "priority",
            "clock":            "clock",
            # SG-NET-01: CAPE's own routing field. Before this the network
            # decision only ever reached CAPE inside the free-text `options`
            # string as `network=...`, which CAPE does not interpret as a
            # route, so every task ran with the server's default routing.
            "route":            "route",
        }
        for k, v in options.items():
            if k in field_map:
                data[field_map[k]] = v

        with open(sample_path, "rb") as f:
            files = {"file": (Path(sample_path).name, f)}
            r = self._session.post(url, files=files, data=data, timeout=60)

        if r.status_code not in (200, 201):
            raise RuntimeError(
                f"CAPE submit failed (HTTP {r.status_code}): {r.text[:200]}"
            )

        result = r.json()
        task_id = result.get("data", {}).get("task_ids", [None])[0] \
                  or result.get("task_id")
        if not task_id:
            raise RuntimeError(f"No task_id in CAPE response: {result}")

        logger.info("[CAPEClient] Submitted. task_id=%d", task_id)
        return int(task_id)

    def _status_rest(self, task_id: int) -> str:
        url = f"{self.cfg.url}/apiv2/tasks/view/{task_id}/"
        r   = self._require_session().get(url, timeout=10)
        if r.status_code == 404:
            return "not_found"
        _require_ok(r, context=f"status check for task {task_id}")
        data = r.json()
        return data.get("data", {}).get("status", "unknown")

    def _report_rest(self, task_id: int) -> dict:
        url = f"{self.cfg.url}/apiv2/tasks/report/{task_id}/"
        r   = self._require_session().get(url, timeout=30)
        if r.status_code == 404:
            raise FileNotFoundError(f"Report not found for task {task_id}")
        _require_ok(r, context=f"report fetch for task {task_id}")
        return r.json()

    def _machines_rest(self) -> list:
        url = f"{self.cfg.url}/apiv2/machines/list/"
        r   = self._require_session().get(url, timeout=10)
        if r.status_code == 404:
            # Endpoint may be disabled — return empty list
            logger.warning("[CAPEClient] machines/list endpoint not available")
            return []
        _require_ok(r, context="machines list")
        data = r.json()
        machines = data.get("data", [])
        if isinstance(machines, list):
            return machines
        return machines.get("machines", [])

    # ------------------------------------------------------------------
    # Local mode implementation
    # ------------------------------------------------------------------

    def _submit_local(self, sample_path: str, options: dict) -> int:
        """Submit via CAPEv2's Python API directly."""
        cape_root = self.cfg.cape_root

        # SG-CTL-01: this used to build one shell string and run it through
        # `bash -c` under `shell=True`. Quoting each interpolation with
        # shlex.quote() made it correct, but correctness then depended on
        # every future edit remembering to quote — and the audit's acceptance
        # criterion is a static gate that rejects `shell=True` outright, not a
        # review of whether each interpolation happens to be safe.
        #
        # As argv there is no shell grammar to escape from, so quoting is not
        # needed and cannot be forgotten. `cd X && …` becomes `docker exec -w`.
        # The token validation stays: CAPE's own flags are enums, and a value
        # outside them should be refused here rather than passed down.
        argv = ["/etc/poetry/bin/poetry", "run", "python", "utils/submit.py"]

        if options.get("machine"):
            argv += ["--machine", _validate_token("machine", options["machine"])]
        if options.get("package"):
            argv += ["--package", _validate_token("package", options["package"])]
        if options.get("platform"):
            argv += ["--platform", _validate_token("platform", options["platform"])]
        if options.get("timeout"):
            argv += ["--timeout", str(int(options["timeout"]))]
        if options.get("memory"):
            argv.append("--memory")
        if options.get("enforce_timeout"):
            argv.append("--enforce-timeout")
        if options.get("tags"):
            argv += ["--tags", _validate_token("tags", options["tags"])]
        if options.get("options"):
            argv += ["--options", str(options["options"])]
        if options.get("priority"):
            argv += ["--priority", str(int(options["priority"]))]

        argv.append(sample_path)

        if self.cfg.container:
            argv = ["docker", "exec", "-w", cape_root, self.cfg.container, *argv]

        try:
            result = subprocess.run(
                argv, shell=False, capture_output=True, text=True,
                timeout=self.cfg.timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"CAPE submit via docker exec did not complete within "
                f"{self.cfg.timeout}s"
            )
        output = result.stdout + result.stderr

        # Parse task ID from output like:
        # "Success: File "..." added as task with ID 5"
        m = re.search(r"task with ID (\d+)", output)
        if not m:
            raise RuntimeError(
                f"Could not parse task ID from submit output: {output[:200]}"
            )

        task_id = int(m.group(1))
        logger.info("[CAPEClient] Submitted locally. task_id=%d", task_id)
        return task_id

    def _status_local(self, task_id: int) -> str:
        """Get task status via REST (even in local mode, REST is available)."""
        try:
            import requests
            r = requests.get(
                f"{self.cfg.url}/apiv2/tasks/view/{task_id}/",
                timeout=5,
                verify=self.cfg.ca_bundle or self.cfg.verify_ssl,
            )
            if r.status_code == 200:
                return r.json().get("data", {}).get("status", "unknown")
        except Exception:
            pass

        # Fallback: check report file existence
        report = Path(self.cfg.storage) / str(task_id) / "reports" / "report.json"
        if report.exists():
            return "reported"

        analysis_dir = Path(self.cfg.storage) / str(task_id)
        if analysis_dir.exists():
            return "running"

        return "pending"

    def _machines_local(self) -> list:
        """Read available machines from kvm.conf."""
        conf_path = Path(self.cfg.cape_root) / "conf" / "kvm.conf"
        if not conf_path.exists():
            return []

        machines = []
        try:
            import configparser
            cfg = configparser.ConfigParser()
            cfg.read(str(conf_path))

            # Get list of machine names
            machine_names = cfg.get("kvm", "machines", fallback="").split(",")
            machine_names = [m.strip() for m in machine_names if m.strip()]

            for name in machine_names:
                if cfg.has_section(name):
                    machines.append({
                        "name":     name,
                        "label":    cfg.get(name, "label",    fallback=name),
                        "platform": cfg.get(name, "platform", fallback="windows"),
                        "tags":     cfg.get(name, "tags",     fallback="").split(","),
                        "arch":     cfg.get(name, "arch",     fallback="x86"),
                        "status":   "available",
                    })
        except Exception as e:
            logger.warning("[CAPEClient] Could not parse kvm.conf: %s", e)

        return machines

    def _report_via_docker(self, task_id: int) -> dict:
        """
        Read report via docker exec, trying cfg.storage first and then a
        set of known-good fallback storage roots (the container's actual
        layout has been observed to vary between deployments).
        """
        task_id = int(task_id)  # fail closed on non-numeric input
        roots = [self.cfg.storage] + [
            r for r in self._STORAGE_ROOT_CANDIDATES if r != self.cfg.storage
        ]
        errors = []
        for root in roots:
            report_path = f"{root.rstrip('/')}/{task_id}/reports/report.json"
            argv = ["docker", "exec", self.cfg.container, "cat", report_path]
            try:
                result = subprocess.run(
                    argv, shell=False, capture_output=True, text=True,
                    timeout=self.cfg.timeout,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{root}: docker exec timed out after {self.cfg.timeout}s")
                continue
            if result.returncode == 0 and result.stdout.strip():
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    errors.append(f"{root}: invalid JSON ({e})")
                    continue
            errors.append(f"{root}: {result.stderr.strip()[:200] or 'not found'}")

        raise FileNotFoundError(
            f"Could not read report for task {task_id} via docker in any of "
            f"{roots}: {'; '.join(errors)}"
        )


def _mode_of(config_path):
    if not config_path:
        return "local"
    try:
        import yaml
        with open(config_path) as f:
            return (yaml.safe_load(f) or {}).get("mode", "local")
    except Exception:
        return "local"


def build_cape_client(config_path: str = None, *, connect: bool = False):
    """
    Build the analysis backend named by cape.yaml's `mode`.

    mode: rest|local -> CAPEClient (a real CAPEv2 deployment)
    mode: qemu       -> QemuCapeClient (TCG Linux/Windows guests; no KVM required)

    Does not reach the backend unless `connect=True`; the orchestrator calls
    `client.connect()` right before the Executor stage.
    """
    if _mode_of(config_path) == "qemu":
        from core.qemu_backend import build_qemu_client
        return build_qemu_client(config_path, connect=connect)
    cfg = CAPEConfig.from_yaml(config_path) if config_path else CAPEConfig()
    return CAPEClient(cfg, connect=connect)
