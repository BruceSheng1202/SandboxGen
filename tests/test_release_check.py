"""Verify that release checks reject sensitive files without echoing their data."""
import importlib.util
import json
from pathlib import Path
import subprocess


SCRIPT = Path(__file__).resolve().parents[1] / "tools/check_release.py"
spec = importlib.util.spec_from_file_location("release_check", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def test_detects_secret_identity_and_binary_without_disclosing_values(tmp_path):
    secret = "sk-" + "z" * 35
    text = secret + "\n" + "/home/" + "example-owner/project/\n"
    (tmp_path / "notes.txt").write_text(text)
    (tmp_path / "unexpected.exe").write_bytes(b"MZ\0synthetic")
    result = checker.inspect(tmp_path)
    rules = {x["rule"] for x in result["findings"]}
    assert {"provider-token", "named-home", "binary-file"} <= rules
    assert secret not in json.dumps(result)
    assert "example-owner" not in json.dumps(result)


def test_scans_tracked_private_config_even_when_gitignored(tmp_path):
    # A separate temporary Git index; no commit, identity or remote is created.
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "config").mkdir()
    (tmp_path / "config/llm.yaml").write_text("api_key: unused\n")
    (tmp_path / ".gitignore").write_text("config/*.yaml\n")
    subprocess.run(["git", "add", "-f", "config/llm.yaml"], cwd=tmp_path, check=True)
    result = checker.inspect(tmp_path)
    assert any(x["rule"] == "private-config" for x in result["findings"])


def test_private_name_matching_does_not_rewrite_unrelated_words(tmp_path):
    (tmp_path / "notes.txt").write_text("allocation\n")
    assert checker.inspect(tmp_path, ["cat"])["passed"]
    (tmp_path / "notes.txt").write_text("owner: cat\n")
    assert not checker.inspect(tmp_path, ["cat"])["passed"]
