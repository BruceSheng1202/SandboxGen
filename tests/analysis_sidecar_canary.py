"""Compute-node canary for the real static-analysis image; benign fixtures only.

Uses the production broker and container entrypoint, with a private Podman
store. Does not call an LLM, download a sample, or boot a detonation VM.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-archive", required=True, type=Path)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    runtime = args.work / "xdg"
    runtime.mkdir(mode=0o700)
    storage_conf = args.work / "storage.conf"
    containers_conf = args.work / "containers.conf"
    storage_conf.write_text(
        '[storage]\ndriver = "overlay"\n'
        f'rootless_storage_path = "{args.work}/store"\n'
        f'runroot = "{runtime}/containers"\n'
    )
    containers_conf.write_text(
        '[engine]\ncgroup_manager = "cgroupfs"\n'
        '[network]\nnetwork_backend = "cni"\n'
        'default_rootless_network_cmd = "slirp4netns"\n'
    )
    os.environ.update({
        "XDG_RUNTIME_DIR": str(runtime),
        "CONTAINERS_STORAGE_CONF": str(storage_conf),
        "CONTAINERS_CONF": str(containers_conf),
        "SANDBOXGEN_ANALYZE_CONTAINER": "1",
        "SANDBOXGEN_PODMAN": "podman",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    subprocess.run(["podman", "load", "-i", str(args.image_archive)], check=True, timeout=240)
    # Production uses a per-job Podman API socket. The broker deliberately
    # strips environment variables; selecting this socket in argv keeps the
    # private engine/store without passing host credentials to subprocesses.
    api_socket = runtime / "podman.sock"
    endpoint = f"unix://{api_socket}"
    os.environ["SANDBOXGEN_PODMAN"] = f"podman --remote --url {endpoint}"
    with (args.work / "podman-service.log").open("w") as service_log:
        service = subprocess.Popen(
            ["podman", "system", "service", "--time=0", endpoint],
            stdout=service_log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while not api_socket.exists():
                if service.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("private Podman API did not start; inspect podman-service.log")
                time.sleep(0.1)
            run_checks(args)
        finally:
            service.terminate()
            try:
                service.wait(timeout=5)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait()


def run_checks(args):
    source = Path(__file__).resolve().parents[1] / "src"
    sys.path.insert(0, str(source))
    from core.agent_loop import AgentLoop
    from core.env_spec import EnvironmentSpec
    from core.workflow_log import WorkflowLog

    source_file = source / "core" / "agent_loop.py"
    source_sha = hashlib.sha256(source_file.read_bytes()).hexdigest()
    workspace = args.work / "workspace"
    sample = args.work / "benign.txt"
    sample.write_text("SandboxGEN harmless static-analysis fixture\n")
    spec = EnvironmentSpec(workspace, "sidecar-canary")
    spec.set("sample.path", str(sample), actor="controller")
    spec.set("cape_submission.package", "exe", actor="controller")
    loop = AgentLoop(None, "x", spec, WorkflowLog(workspace, "canary"), "Scout")
    spec_file = workspace / "environment_spec.json"
    results = []

    def check(operation, target, expected, options=None):
        before = spec_file.read_bytes()
        stamp = spec_file.stat()
        result = loop._tool_analyze_sample({"operation": operation, "path": str(target), "options": options or {}})
        assert expected in result, (operation, result)
        assert spec_file.read_bytes() == before, f"{operation}: controller spec changed"
        assert spec_file.stat().st_ino == stamp.st_ino
        assert spec_file.stat().st_mtime_ns == stamp.st_mtime_ns
        disk = loop._execute_tool({"tool": "read_file", "path": "environment_spec.json"})["result"]
        memory = loop._execute_tool({"tool": "read_spec"})["result"]
        assert json.loads(disk) == json.loads(memory)
        results.append({"operation": operation, "passed": True, "result_preview": result[:180]})

    check("identify", sample, "sha256=")
    check("file", sample, "text")
    spec.set("cape_submission.timeout", 120, actor="controller")
    check("identify", sample, "sha256=")
    check("identify", workspace / "missing.txt", "ERROR")
    archive = workspace / "benign.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("hello.txt", "benign extraction fixture")
    check("zip_extract", archive, "OK", {"dest": "unpacked"})
    assert (workspace / "unpacked" / "hello.txt").read_text() == "benign extraction fixture"
    check("zip_extract", archive, "ERROR", {"dest": str(args.work / "outside")})
    assert not (args.work / "outside").exists()
    assert not list((workspace / ".analyze").glob("req_*.json"))
    containers = subprocess.run(["podman", "ps", "-aq"], capture_output=True, text=True, check=True)
    assert not containers.stdout.strip(), "canary containers remain"
    assert hashlib.sha256(source_file.read_bytes()).hexdigest() == source_sha
    summary = {
        "passed": True, "node": socket.gethostname(), "checks": results,
        "source_sha256": source_sha, "code_unchanged": True,
        "containers_remaining": 0, "scope": "benign static sidecar only; no LLM or malware",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
