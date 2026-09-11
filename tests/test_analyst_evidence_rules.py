"""Guardrails that keep harness/background activity out of final findings."""

from __future__ import annotations

import sys
from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from agents.analyst import SYSTEM_PROMPT  # noqa: E402


def test_prompt_explicitly_excludes_qemu_background_noise():
    assert "background_noise_not_sample_behavior" in SYSTEM_PROMPT
    assert "Never use it" in SYSTEM_PROMPT
    assert "harness `schtasks.exe`" in SYSTEM_PROMPT


def test_prompt_requires_observed_evidence_for_attack_mapping():
    assert "must directly show the action" in SYSTEM_PROMPT
    assert "embedded installer writing/extracting its own MSI is not T1105" in SYSTEM_PROMPT
    assert "certificate" in SYSTEM_PROMPT
    assert "validation and vendor/origin-check lookups are not C2" in SYSTEM_PROMPT
