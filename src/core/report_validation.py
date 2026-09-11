"""Shared structural and artifact checks; never generate or repair model findings."""

import json
import os
import re
import stat
from pathlib import Path
from typing import Optional

# ── Final report schema (SG-INT-02 / round-1 INT-08) ─────────────────────────
_REPORT_REQUIRED: dict[str, type | tuple] = {
    "classification":    str,
    "confidence":        str,
    "behaviour_summary": list,
    "iocs":              list,
    "mitre_attack":      list,
}
_REPORT_CONFIDENCE = frozenset({"high", "medium", "low", "unknown"})
_IOC_TYPES = frozenset({
    "ip", "domain", "url", "sha256", "sha1", "md5", "mutex",
    "registry_key", "file_path", "email", "user_agent", "other",
    # Indicator types real samples legitimately produce that the original
    # whitelist lacked. A live Mirai run classified correctly (ddos_bot) but
    # was fail-closed because it reported a Telegram C2 channel (t.me/...):
    # a descriptive label, not a security-relevant field, must never discard
    # an otherwise-valid analysis. Known modern C2/host indicators are kept
    # first-class here; anything still outside is coerced to "other" by
    # _normalize_report before validation.
    "telegram", "discord", "tor_onion", "onion", "process_name",
    "cmdline", "port", "hostname", "filename", "yara_rule", "asn",
})
_MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?\b")


def _normalize_report(report):
    """
    Return a copy of an Analyst report safe for promotion. Coerces any IOC
    whose `type` the whitelist does not recognise to "other", preserving the
    original label as `raw_type`, so a descriptive-but-unknown IOC type never
    fail-closes an otherwise-valid, correct analysis (a live Mirai run was
    discarded whole because one IOC was typed 'telegram'). Structural and
    provenance validity is still enforced by validate_report on the result.
    """
    if not isinstance(report, dict):
        return report
    iocs = report.get("iocs")
    if not isinstance(iocs, list):
        return report
    out = dict(report)
    normalized = []
    for ioc in iocs:
        if isinstance(ioc, dict) and isinstance(ioc.get("type"), str) and ioc["type"] not in _IOC_TYPES:
            ioc = dict(ioc)
            ioc["raw_type"] = ioc["type"]
            ioc["type"] = "other"
        normalized.append(ioc)
    out["iocs"] = normalized
    return out


def validate_report(report, *, expected_task_id: Optional[int]) -> list[str]:
    """
    Structural and provenance checks on an Analyst report. Returns a list of
    problems; empty means the report may be promoted.

    Provenance: when the ledger has a verified report, the Analyst's
    `cape_task_id` must name that task — an Analyst that quotes another task
    (a neighbour it queried while troubleshooting, or one it invented) does
    not get its conclusions promoted.
    """
    problems: list[str] = []
    if not isinstance(report, dict):
        return [f"report must be a JSON object, got {type(report).__name__}"]
    for key, typ in _REPORT_REQUIRED.items():
        if key not in report:
            problems.append(f"missing required field {key!r}")
        elif not isinstance(report[key], typ):
            problems.append(f"{key} must be {typ.__name__}, got {type(report[key]).__name__}")
    if isinstance(report.get("confidence"), str) and report["confidence"] not in _REPORT_CONFIDENCE:
        problems.append(f"confidence must be one of {sorted(_REPORT_CONFIDENCE)}")
    for i, ioc in enumerate(report.get("iocs") if isinstance(report.get("iocs"), list) else []):
        if not isinstance(ioc, dict) or "type" not in ioc or "value" not in ioc:
            problems.append(f"iocs[{i}] must be an object with 'type' and 'value'")
            continue
        if not isinstance(ioc["type"], str) or ioc["type"] not in _IOC_TYPES:
            problems.append(f"iocs[{i}].type {ioc['type']!r} is not a known IOC type")
        if not isinstance(ioc["value"], str) or not ioc["value"].strip():
            problems.append(f"iocs[{i}].value must be a non-empty string")
    for i, t in enumerate(report.get("mitre_attack") if isinstance(report.get("mitre_attack"), list) else []):
        if not isinstance(t, str) or not _MITRE_ID.match(t.strip()):
            problems.append(f"mitre_attack[{i}] {t!r} is not a Txxxx technique id")
    if expected_task_id is not None:
        claimed = report.get("cape_task_id")
        if isinstance(claimed, bool) or not isinstance(claimed, int) or claimed != expected_task_id:
            problems.append(
                f"cape_task_id {claimed!r} does not name the verified task {expected_task_id}"
            )
    return problems


def completion_problems(report, workspace: Path, expected_task_id=None):
    """Require the model's structured result and matching standalone delivery."""
    candidate = _normalize_report(report)
    problems = validate_report(candidate, expected_task_id=expected_task_id)
    if problems:
        return ["analysis.report: " + problem for problem in problems]
    path = Path(workspace) / "analysis_report.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 20_000_000:
                return ["analysis_report.json must be a regular JSON file <= 20 MB"]
            standalone = _normalize_report(json.load(handle))
    except (OSError, ValueError) as exc:
        return [f"write_file must create a valid analysis_report.json: {exc}"]
    problems = validate_report(standalone, expected_task_id=expected_task_id)
    if problems:
        return ["analysis_report.json: " + problem for problem in problems]
    if standalone != candidate:
        return ["analysis_report.json must contain the same report as analysis.report"]
    return []
