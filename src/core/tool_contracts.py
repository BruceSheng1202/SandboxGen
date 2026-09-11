"""The flat JSON contract shared by prompts and the tool dispatcher."""

import json

from core.spec_policy import ROLE_TOOLS


EXAMPLES = {
    "read_spec": {"path": "cape_submission"},
    "update_spec": {"key": "cape_submission.package", "value": "exe"},
    "append_spec": {"key": "classification.basis", "value": "observed evidence"},
    "read_file": {"path": "environment_spec.json", "offset": 0, "limit": 4000},
    "write_file": {"path": "analysis_report.json", "content": "{\"classification\":\"unknown\"}"},
    "query_json": {"file": "environment_spec.json", "path": "cape_submission", "limit": 20},
    "analyze_sample": {"operation": "identify", "path": "/actual/sample/path"},
    "log_decision": {"message": "decision", "reasoning": "supporting evidence"},
    "log_observation": {"message": "observed evidence"},
    "finish": {"summary": "Completed the required outputs; limitations are recorded."},
    "fetch_url": {"url": "https://example.org/sample", "dest": "downloads/sample"},
    "clone_repo": {"url": "https://example.org/repo.git", "dest": "downloads/repo"},
    "mb_lookup": {"sha256": "sample SHA256 from run facts"},
    "cape_service_check": {},
    "cape_vm_start": {"vm_name": "actual available VM name"},
    "cape_submit": {"package": "exe", "timeout": 120},
    "cape_status": {"task_id": 123},
    "cape_fetch_report": {"task_id": 123},
}

# Validate the common state/file/completion interface before interpreting
# paths or setting finished=True. A missing field is never silently empty.
REQUIRED = {
    "read_spec": {},
    "read_file": {"path": str},
    "write_file": {"path": str, "content": str},
    "update_spec": {"key": str, "value": object},
    "append_spec": {"key": str, "value": object},
    "query_json": {"file": str},
    "finish": {"summary": str},
}


def validate_call(call):
    if not isinstance(call, dict) or not isinstance(call.get("tool"), str) or not call["tool"].strip():
        return "ERROR: tool must be a non-empty string in a JSON object."
    tool = call.get("tool", "")
    if "arguments" in call or "parameters" in call:
        return f"ERROR: {tool} uses flat top-level fields, not nested arguments/parameters."
    for key, kind in REQUIRED.get(tool, {}).items():
        if key not in call or not isinstance(call[key], kind):
            return f"ERROR: {tool} requires top-level '{key}' ({kind.__name__}). Use flat JSON, not positional or nested arguments."
        if kind is str and key != "content" and not call[key].strip():
            return f"ERROR: {tool}.{key} must be a non-empty string."
    if tool in {"read_spec", "read_file", "query_json"}:
        if "path" in call and not isinstance(call["path"], str):
            return f"ERROR: {tool}.path must be a string."
        for key, minimum in (("offset", 0), ("limit", 1)):
            if key in call and (type(call[key]) is not int or call[key] < minimum):
                return f"ERROR: {tool}.{key} must be an integer >= {minimum}."
    return None


def tool_contract(role):
    allowed = ROLE_TOOLS.get(role, frozenset({"finish"}))
    examples = []
    for tool in sorted(allowed):
        fields = EXAMPLES[tool]
        if tool == "update_spec" and role == "Analyst":
            fields = {"key": "analysis.report", "value": {"classification": "unknown", "confidence": "low",
                      "cape_task_id": 123, "behaviour_summary": [], "iocs": [], "mitre_attack": []}}
        examples.append(json.dumps({"tool": tool, **fields}))
    return (
        "\n\nAUTHORITATIVE TOOL CONTRACT\n"
        "Emit one or more <tool_call>JSON_OBJECT</tool_call> blocks. Each object uses the flat, named fields below. "
        "Do not put fields inside arguments/parameters, and do not emit Python calls. Examples show syntax, not sample findings; "
        "replace example values with the actual run facts.\n"
        "read_spec with no path reads the shared state; path selects a dotted subtree. "
        "offset/limit optionally page list items or dictionary keys. read_file offset/limit count characters. "
        "Truncation is explicitly marked; request a narrower path or the next page when needed.\n"
        "write_file requires path and content (a string; JSON-encode report objects). "
        "finish requires a non-empty summary and does not create or repair outputs.\n"
        + "\n".join(examples)
    )
