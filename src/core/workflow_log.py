#!/usr/bin/env python3
"""
core/workflow_log.py — Workflow Logger

Records every action, decision, and observation across all agents.
Produces:
  - workflow.json       — structured machine-readable log
  - workflow_report.txt — human-readable report with clear stage/agent markers
"""

import json
import os
import re
import time
import logging
from pathlib import Path
from datetime import datetime, timezone

from core.redact import redact as _redact


# Console logger
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] amsa: %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S,%f"[:-3],
)
logger = logging.getLogger("amsa")


def _redact_value(value):
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, dict):
        return {k: ("<REDACTED>" if re.fullmatch(r"(?i)(api[_-]?key|authorization|password|access[_-]?token|secret)", str(k))
                    else _redact_value(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


class WorkflowLog:
    def __init__(self, workspace: Path, run_id: str):
        self.workspace = workspace
        self.run_id    = run_id
        self._entries  = []
        self._stages   = []
        self._current_stage = None
        self._stage_start_time = None
        self._trace_sequence = 0

    def trace(self, agent: str, event: str, data: dict):
        """Persist exchanges and provider evidence apart from console summaries.

        Provider response fields (including reasoning when supplied) are local
        diagnostic evidence, redacted here and never fed to the tool executor.
        Each complete JSONL line survives a later exception or scheduler stop.
        """
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._trace_sequence += 1
        record = {"run_id": self.run_id, "sequence": self._trace_sequence,
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "agent": agent, "event": event, "data": _redact_value(data)}
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
        fd = os.open(self.workspace / "agent_trace.jsonl", flags, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    # ------------------------------------------------------------------

    def _entry(self, level: str, agent: str, message: str, data: dict = None):
        # INT-12 fix: redact secret-shaped substrings from everything this
        # logger persists, not just the one call site (analyze_sample) that
        # previously redacted manually before calling tool_call(). Agent
        # messages/reasoning/observations can echo back tool output or
        # LLM-visible environment values, so redaction belongs here, at the
        # single point everything funnels through, rather than at each of
        # the ~15 call sites in agent_loop.py.
        message = _redact(message)
        if data:
            data = _redact_value(data)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     level,
            "agent":     agent,
            "message":   message,
        }
        if data:
            entry["data"] = data
        self._entries.append(entry)

        # Console output with agent prefix
        prefix = f"[{agent}]"
        if level == "ERROR":
            logger.error("%s %s", prefix, message)
        elif level == "WARNING":
            logger.warning("%s %s", prefix, message)
        else:
            logger.info("%s %s", prefix, message)

        return entry

    def info(self, agent: str, message: str, data: dict = None):
        return self._entry("INFO", agent, message, data)

    def warning(self, agent: str, message: str, data: dict = None):
        return self._entry("WARNING", agent, message, data)

    def error(self, agent: str, message: str, data: dict = None):
        return self._entry("ERROR", agent, message, data)

    def decision(self, agent: str, message: str, reasoning: str = None):
        data = {"reasoning": reasoning} if reasoning else None
        entry = self._entry("DECISION", agent, message, data)
        logger.info("[%s] DECISION: %s", agent, message)
        if reasoning:
            logger.info("[%s]   Reasoning: %s", agent, reasoning)
        return entry

    def tool_call(self, agent: str, tool: str, command: str, result: str = None):
        data = {"tool": tool, "command": command}
        if result:
            data["result_preview"] = result[:200]
        return self._entry("TOOL", agent, f"Tool: {tool} → {command[:80]}", data)

    def observation(self, agent: str, message: str, data: dict = None):
        return self._entry("OBSERVATION", agent, message, data)

    # ------------------------------------------------------------------

    def stage_start(self, stage: str, description: str):
        self._current_stage     = stage
        self._stage_start_time  = time.time()
        self._entry("STAGE_START", stage, f"=== {stage.upper()} STAGE STARTED === {description}")
        logger.info("=" * 60)
        logger.info("AMSA — Stage: %s — %s", stage, description)
        logger.info("=" * 60)

    def stage_end(self, stage: str, summary: str):
        duration = time.time() - (self._stage_start_time or time.time())
        self._stages.append({
            "stage":       stage,
            "summary":     summary,
            "duration_s":  round(duration, 1),
        })
        self._entry("STAGE_END", stage,
                    f"=== {stage.upper()} STAGE COMPLETE === {summary} [{duration:.1f}s]")
        logger.info("[%s] Stage complete in %.1fs: %s", stage, duration, summary)

    # ------------------------------------------------------------------

    def save_json(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "run_id":  self.run_id,
                "stages":  self._stages,
                "entries": self._entries,
            }, f, indent=2)

    def save_text_report(self, path: Path, spec):
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        sep   = "=" * 70

        lines += [
            sep,
            "AMSA — AGENTIC MALWARE SANDBOX ANALYSER",
            "Workflow Report",
            sep,
            f"Run ID:    {self.run_id}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        # Sample info
        sample = spec.get("sample") or {}
        lines += [
            sep,
            "SAMPLE",
            sep,
            f"  Path:      {sample.get('path', 'N/A')}",
            f"  SHA256:    {sample.get('sha256', 'N/A')}",
            f"  File type: {sample.get('file_type', 'N/A')}",
            f"  Size:      {sample.get('size_bytes', 'N/A')} bytes",
            "",
        ]

        # Classification
        clf = spec.get("classification") or {}
        lines += [
            sep,
            "CLASSIFICATION",
            sep,
            f"  Type:       {clf.get('type', 'unknown')}",
            f"  Confidence: {clf.get('confidence', 'unknown')}",
            f"  Family:     {clf.get('family', 'unknown')}",
            f"  Basis:",
        ]
        for b in (clf.get("basis") or []):
            lines.append(f"    • {b}")
        lines.append("")

        # Stage summaries
        lines += [sep, "STAGE SUMMARY", sep]
        for s in self._stages:
            icon = "✓"
            lines.append(f"  [{icon}] {s['stage']:<12} {s['duration_s']:>6.1f}s  {s['summary']}")
        lines.append("")

        # Full workflow log
        lines += [sep, "FULL WORKFLOW LOG", sep]
        current_stage = None
        for e in self._entries:
            agent = e.get("agent", "?")
            msg   = e.get("message", "")
            level = e.get("level", "INFO")
            ts    = e.get("timestamp", "")[:19].replace("T", " ")

            # Stage boundary markers
            if level == "STAGE_START":
                lines += ["", f"  ┌─ {msg} ─┐", ""]
                current_stage = agent
                continue
            if level == "STAGE_END":
                lines += ["", f"  └─ {msg} ─┘", ""]
                continue

            # Level prefix
            prefix = {
                "INFO":        "   ",
                "WARNING":     " ! ",
                "ERROR":       "ERR",
                "DECISION":    ">>>",
                "TOOL":        "  →",
                "OBSERVATION": "  *",
            }.get(level, "   ")

            lines.append(f"  {ts}  {prefix} [{agent}] {msg}")

            # Include reasoning if present
            data = e.get("data", {})
            if data and data.get("reasoning"):
                lines.append(f"                        Reasoning: {data['reasoning']}")

        lines.append("")

        # Final report
        report = spec.get("report") or {}
        if isinstance(report, str):
            report = {"classification": "unknown", "note": f"Invalid report value: {report}"}
        if report:
            lines += [sep, "ANALYSIS REPORT", sep]
            lines.append(f"  Classification:  {report.get('classification', 'unknown')}")
            lines.append(f"  Confidence:      {report.get('confidence', 'unknown')}")
            lines.append(f"  Behaviour:")
            for b in (report.get("behaviour_summary") or []):
                lines.append(f"    • {b}")
            lines.append(f"  IOCs ({len(report.get('iocs', []))}):")
            for ioc in (report.get("iocs") or [])[:20]:
                lines.append(f"    • [{ioc.get('type')}] {ioc.get('value')}")
            lines.append(f"  MITRE ATT&CK:")
            for t in (report.get("mitre_attack") or []):
                lines.append(f"    • {t}")
            lines.append(f"  Detections:")
            for d in (report.get("recommended_detections") or []):
                lines.append(f"    • {d}")
            lines.append("")

        # Token usage / cost
        usage = spec.get("token_usage") or {}
        if usage:
            cost = usage.get("cost_usd")
            cost_str = f"${cost:.4f}" if cost is not None else "unknown (set price_input_per_mtok / price_output_per_mtok in llm.yaml)"
            lines += [
                sep,
                "TOKEN USAGE / COST",
                sep,
                f"  Model:          {usage.get('model', 'unknown')}",
                f"  LLM calls:      {usage.get('calls', 0)}",
                f"  Input tokens:   {usage.get('input_tokens', 0)}",
                f"  Output tokens:  {usage.get('output_tokens', 0)}",
                f"  Total tokens:   {usage.get('total_tokens', 0)}",
                f"  Estimated cost: {cost_str}",
                "",
            ]

        lines.append(sep)

        with open(path, "w") as f:
            f.write("\n".join(lines))

    def print_summary(self):
        print("\n" + "=" * 60)
        print("AMSA — PIPELINE COMPLETE")
        print("=" * 60)
        for s in self._stages:
            print(f"  [✓] {s['stage']:<12} {s['duration_s']:>6.1f}s  {s['summary']}")
        print("=" * 60)
