#!/usr/bin/env python3
"""Inspect release candidates without printing secrets or executing project code."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
CACHE_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
FORBIDDEN_DIRS = {".codex", ".agents", "samples", "sample_pool", "quarantine",
                  "results", "workspace", "workspaces", "vmstore", "vm-assets",
                  "data", "experiments", "private", "mlruns", "mlartifacts"}
FORBIDDEN_SUFFIXES = {".exe", ".dll", ".elf", ".apk", ".bin", ".zip", ".rar",
                      ".7z", ".gz", ".tar", ".qcow2", ".iso", ".img", ".pcap",
                      ".pcapng", ".dmp", ".sqlite", ".db", ".log", ".jsonl",
                      ".pyc", ".pem", ".key"}
PATTERNS = {
    "provider-token": re.compile(r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{20,}|"
                                 r"gh[pousr]_[A-Za-z0-9]{25,}|"
                                 r"github_pat_[A-Za-z0-9_]{25,}|"
                                 r"AIza[\w-]{30,}|AKIA[A-Z0-9]{16})\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\."
                      r"[A-Za-z0-9_-]+"),
    "paired-api-token": re.compile(r"\b[a-f0-9]{32}\.[A-Za-z0-9]{16,}\b"),
    "named-home": re.compile(r"/(?:home|Users)/([A-Za-z0-9_.-]+)/"),
    "named-scratch": re.compile(r"/scratch/([A-Za-z0-9_.-]+)/"),
}


def candidate_files(root):
    probe = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root,
                           capture_output=True, text=True)
    if probe.returncode == 0 and Path(probe.stdout.strip()).resolve() == root:
        raw = subprocess.check_output(["git", "ls-files", "-z", "--cached",
                                       "--others", "--exclude-standard"], cwd=root)
        return sorted({root / s.decode() for s in raw.split(b"\0") if s})
    return sorted(p for p in root.rglob("*")
                  if not CACHE_DIRS.intersection(p.relative_to(root).parts)
                  and (p.is_file() or p.is_symlink()))


def inspect(root, forbidden_text=()):
    findings = []
    files = candidate_files(root)
    allow_file = root / "tools/release_allowlist.json"
    allowed = json.loads(allow_file.read_text()) if allow_file.is_file() else []
    allow = {(x["file"], x["rule"], x["line_sha256"]) for x in allowed}

    def issue(path, rule, line=None):
        item = {"file": str(path.relative_to(root)), "rule": rule}
        if line is not None:
            item["line"] = line
        findings.append(item)

    for path in files:
        rel = path.relative_to(root)
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            issue(path, "symlink-or-outside-root")
            continue
        if FORBIDDEN_DIRS.intersection(rel.parts) or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            issue(path, "runtime-or-private-artifact")
        if "config" in rel.parts and path.suffix in {".yaml", ".yml"}:
            issue(path, "private-config")
        if path.name.startswith(".env") or path.name in {"secrets.env", "model_api_key.md"}:
            issue(path, "credential-file")
        if not path.is_file():
            issue(path, "missing-tracked-file")
            continue
        raw = path.read_bytes()
        if len(raw) > 2_000_000:
            issue(path, "large-file")
        if raw.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b")) or b"\0" in raw:
            issue(path, "binary-file")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            issue(path, "non-utf8-file")
            continue
        if raw and not raw.endswith(b"\n"):
            issue(path, "missing-final-newline")
        for line_no, line in enumerate(text.splitlines(), 1):
            if line.rstrip() != line:
                issue(path, "trailing-whitespace", line_no)
            if re.match(r"^(?:<{7}|={7}|>{7})(?: |$)", line):
                issue(path, "merge-conflict-marker", line_no)
            if any(re.search(r"(?<!\w)" + re.escape(value) + r"(?!\w)",
                             line, re.IGNORECASE) for value in forbidden_text):
                issue(path, "forbidden-private-text", line_no)
            for rule, pattern in PATTERNS.items():
                matches = list(pattern.finditer(line))
                # Generic guest users are intentional, not contributor identity.
                if rule in {"named-home", "named-scratch"}:
                    matches = [m for m in matches if m.group(1).lower()
                               not in {"analyst", "cape"}]
                if matches:
                    fingerprint = hashlib.sha256(line.encode()).hexdigest()
                    if (str(rel), rule, fingerprint) not in allow:
                        issue(path, rule, line_no)
        if path.suffix == ".py":
            try:
                ast.parse(text, filename=str(rel))
            except SyntaxError as exc:
                issue(path, "python-syntax", exc.lineno)
        if path.suffix == ".sh":
            checked = subprocess.run(["bash", "-n", str(path)], capture_output=True)
            if checked.returncode:
                issue(path, "shell-syntax")
        try:
            if path.suffix == ".json":
                json.loads(text)
            elif path.suffix == ".xml":
                ET.fromstring(text)
            elif path.name.endswith((".yaml", ".yml", ".yaml.example", ".yml.example")):
                import yaml
                yaml.safe_load(text)
        except (ValueError, ET.ParseError):
            issue(path, "invalid-structured-file")
        except ImportError:
            issue(path, "yaml-check-needs-PyYAML")
        except Exception:
            # Do not print parser errors: they can echo a secret-bearing line.
            issue(path, "structured-file-check-failed")
        if path.suffix == ".md":
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if urlsplit(target).scheme or target.startswith("#"):
                    continue
                target = unquote(target.split("#", 1)[0].strip("<>"))
                destination = (path.parent / target).resolve()
                if not destination.is_relative_to(root) or not destination.exists():
                    issue(path, "broken-or-external-local-link")
    return {"files_checked": len(files), "passed": not findings, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-text", action="append", default=[],
                        help="Additional private name/host token; not echoed in findings")
    args = parser.parse_args()
    report = inspect(ROOT, args.forbid_text)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
