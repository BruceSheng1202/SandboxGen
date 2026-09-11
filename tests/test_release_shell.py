"""Exercise the real wrapper with a fake engine; no VM, API or malware."""
import json
import os
from pathlib import Path
import socket
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_wrapper_passes_secret_names_and_preserves_sample_mount(tmp_path):
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "golden.qcow2").write_bytes(b"benign image placeholder")
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    samples = tmp_path / "sample dir [one]"
    samples.mkdir()
    cfg = tmp_path / "cape.yaml"
    cfg.write_text(f"mode: qemu\nqemu_vm_dir: {assets}\n"
                   f"qemu_golden: golden.qcow2\nqemu_task_dir: {tasks}\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "podman"
    fake.write_text("#!/usr/bin/env python3\nimport json,os,sys\n"
                    "if sys.argv[1] == 'run':\n"
                    "    with open(os.environ['CAPTURE'], 'w') as f:\n"
                    "        json.dump({'argv': sys.argv[1:], 'present': "
                    "bool(os.environ.get('OPENAI_API_KEY')), 'unset_is_empty': "
                    "os.environ.get('ANTHROPIC_API_KEY') == '' and "
                    "os.environ.get('MALWAREBAZAAR_API_KEY') == ''}, f)\n")
    fake.chmod(0o700)
    capture = tmp_path / "capture.json"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "CAPE_CONFIG": str(cfg), "CAPTURE": str(capture),
           "SANDBOXGEN_SAMPLES_DIR": str(samples),
           "SANDBOXGEN_PODMAN_SOCK": str(tmp_path / "engine.sock"),
           "OPENAI_API_KEY": "synthetic-secret-with-spaces-and-$-characters",
           "SANDBOXGEN_LIVE": "0"}
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("MALWAREBAZAAR_API_KEY", None)
    # The wrapper checks the socket's existence; the fake engine never connects.
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind(env["SANDBOXGEN_PODMAN_SOCK"])
        proc = subprocess.run(["bash", str(ROOT / "src/sandbox_infra/run_pipeline.sh"),
                               "--help"], env=env, capture_output=True, text=True,
                              timeout=20)
    assert proc.returncode == 0, proc.stderr
    seen = json.loads(capture.read_text())
    assert seen["present"] is True
    assert seen["unset_is_empty"] is True
    assert env["OPENAI_API_KEY"] not in json.dumps(seen["argv"])
    assert env["OPENAI_API_KEY"] not in proc.stdout + proc.stderr
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MALWAREBAZAAR_API_KEY"):
        assert seen["argv"][seen["argv"].index(name) - 1] == "-e"
    mount = f"{samples}:{samples}:ro"
    assert seen["argv"][seen["argv"].index(mount) - 1] == "-v"


def test_legacy_provisioner_requires_deployment_paths():
    env = {k: v for k, v in os.environ.items()
           if k not in {"CAPE_WORK_DIR", "CAPE_PGDATA_DIR", "CAPE_VENV"}}
    proc = subprocess.run(["bash", str(ROOT / "src/sandbox_infra/amsa_start.sh")],
                          env=env, capture_output=True, text=True, timeout=5)
    assert proc.returncode != 0
    assert "Set CAPE_WORK_DIR" in proc.stderr
