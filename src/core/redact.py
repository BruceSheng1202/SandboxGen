#!/usr/bin/env python3
"""
core/redact.py — Shared secret-redaction helper.

Extracted from agent_loop.py's CTL-08 fix so WorkflowLog (INT-12) can apply
the same redaction to everything it persists, not just the one call site
that previously called _redact() manually before logging.
"""

import re

_SECRET_PATTERNS = [
    re.compile(r'(Auth-Key:\s*)[^\s\'"]+', re.IGNORECASE),
    re.compile(r'(["\']?api[_-]?key["\']?\s*[:=]\s*["\']?)[^\s"\']+', re.IGNORECASE),
    re.compile(r'(["\']?token["\']?\s*[:=]\s*["\']?)[^\s"\']+', re.IGNORECASE),
    re.compile(r'(["\']?password["\']?\s*[:=]\s*["\']?)[^\s"\']+', re.IGNORECASE),
    # SG-LOG-01: the original list only knew `Bearer`. CAPE's REST API uses
    # Django REST framework's `Token <key>` scheme — the very header
    # cape_client sends — so a logged request line carried the superuser
    # token verbatim. Cover every Authorization scheme, cookies, the common
    # X-Api-Key header, and userinfo embedded in URLs.
    re.compile(r'(Authorization:\s*[A-Za-z-]+\s+)[^\s\'"]+', re.IGNORECASE),
    re.compile(r'(X-Api-Key:\s*)[^\s\'"]+', re.IGNORECASE),
    re.compile(r'((?:Set-)?Cookie:\s*)[^\r\n]+', re.IGNORECASE),
    re.compile(r'(://[^/\s:@]+:)[^@/\s]+(@)'),
    # Bare provider key shapes that appear without a label.
    re.compile(r'\b(sk-(?:ant-)?)[A-Za-z0-9_-]{16,}'),
    re.compile(r'\b(AIza)[A-Za-z0-9_-]{30,}'),
]


def _sub(pat, text: str) -> str:
    # Patterns with two groups keep both delimiters (URL userinfo); the rest
    # keep only the label prefix.
    if pat.groups == 2:
        return pat.sub(r'\1[REDACTED]\2', text)
    return pat.sub(r'\1[REDACTED]', text)


def redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = _sub(pat, text)
    return text
