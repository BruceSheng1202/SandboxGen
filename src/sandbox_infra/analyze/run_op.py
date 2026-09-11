#!/usr/bin/env python3
"""
run_op.py — analyze_sample operation entrypoint for the static-analysis sidecar.

Runs INSIDE a --network none, no-socket, cap-dropped, read-only container
(sandbox_infra/Containerfile.analyze). It parses the untrusted sample using the
harness's own operation handlers, so a parser bug is contained here: no network
to exfiltrate through, no podman socket to abuse. Reads one JSON request file
and prints the operation result to stdout.

request.json: {"operation","path","options","workspace","sample_path","repo"}
"""
import json
import os
import sys

req = json.load(open(sys.argv[1]))
sys.path.insert(0, req["repo"])
# Already isolated by the container; the in-process fork-sandbox would only add
# a redundant setuid/rlimit layer, so skip it here.
os.environ["AMSA_SKIP_SAMPLE_SANDBOX"] = "1"

from core.agent_loop import run_analyze_op_standalone  # noqa: E402

print(run_analyze_op_standalone(
    operation=req["operation"],
    path=req["path"],
    options=req.get("options") or {},
    workspace=req["workspace"],
    sample_path=req.get("sample_path"),
), end="")
