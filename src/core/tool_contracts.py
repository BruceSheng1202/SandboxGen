"""The flat JSON contract shared by prompts and the tool dispatcher."""

import json

from core.spec_policy import ROLE_TOOLS


NETWORK_TOOLS = frozenset({"fetch_url", "clone_repo", "mb_lookup"})
ANALYSIS_OPTIONS = dict.fromkeys((
    "identify", "file", "zip_list", "pe_info", "pe_exports", "macho_info",
    "apk_info", "ole_macros", "ole_meta", "python_ast_summary",
    "readelf_headers", "readelf_dynamic", "readelf_symbols", "nm_dynamic",
    "upx_test", "yara_scan", "diec", "archive_list", "pdf_id",
    "pcap_top_talkers", "pcap_dns_queries", "pcap_tls_sni",
), frozenset())
ANALYSIS_OPTIONS.update({
    "strings": frozenset({"min_length", "offset", "limit"}),
    "strings_utf16": frozenset({"min_length", "offset", "limit"}),
    "grep": frozenset({"pattern", "offset", "limit"}),
    "find_files": frozenset({"extension"}),
    "zip_extract": frozenset({"dest", "password"}),
    "archive_extract": frozenset({"dest"}),
    "apktool_unpack": frozenset({"dest"}),
})


EXAMPLES = {
    "read_spec": {"path": "cape_submission"},
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

# State-writing examples must respect the same role ACL as the dispatcher.
ROLE_SPEC_EXAMPLES = {
    "Scout": {
        "update_spec": {"key": "classification.confidence", "value": "low"},
        "append_spec": {"key": "classification.basis", "value": "observed evidence"},
    },
    "Architect": {
        "update_spec": {"key": "cape_submission.package", "value": "exe"},
        "append_spec": {"key": "architect.observations", "value": "observed evidence"},
    },
    "Executor": {
        "update_spec": {"key": "executor.current_pass", "value": 1},
        "append_spec": {"key": "executor.observations", "value": "observed evidence"},
    },
    "Analyst": {
        "update_spec": {"key": "analysis.report", "value": {
            "classification": "unknown", "confidence": "low", "cape_task_id": 123,
            "behaviour_summary": [], "iocs": [], "mitre_attack": [],
        }},
        "append_spec": {"key": "analyst.observations", "value": "observed evidence"},
    },
}

# Validate the common state/file/completion interface before interpreting
# paths or setting finished=True. A missing field is never silently empty.
REQUIRED = {
    "analyze_sample": {"operation": str, "path": str},
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
    if tool == "analyze_sample":
        operation = call["operation"]
        allowed = ANALYSIS_OPTIONS.get(operation)
        if allowed is None:
            return (f"ERROR: unknown analyze_sample operation {operation!r}. "
                    f"Valid operations: {', '.join(sorted(ANALYSIS_OPTIONS))}")
        options = call.get("options")
        if options is None:
            options = {}
        if not isinstance(options, dict):
            return "ERROR: analyze_sample.options must be a JSON object."
        unknown = set(options) - allowed
        if unknown:
            return (f"ERROR: {operation} does not support options {', '.join(sorted(unknown))}. "
                    f"Supported options: {', '.join(sorted(allowed)) or '(none)'}. "
                    "No operation was run; options are not silently ignored.")
        for key, value in options.items():
            if key in {"offset", "limit", "min_length"}:
                minimum = 0 if key == "offset" else 1
                if type(value) is not int or value < minimum:
                    return f"ERROR: {operation}.options.{key} must be an integer >= {minimum}."
                if key == "min_length" and value > 4096:
                    return "ERROR: min_length must be <= 4096."
            elif not isinstance(value, str):
                return f"ERROR: {operation}.options.{key} must be a string."
    return None


def tool_contract(role, allow_sample_download=False):
    allowed = ROLE_TOOLS.get(role, frozenset({"finish"}))
    downloads_enabled = role == "Scout" and allow_sample_download
    if not downloads_enabled:
        allowed = allowed - NETWORK_TOOLS
    availability = (
        "Network tools are enabled only to acquire the requested URL/repository input.\n"
        if downloads_enabled else
        "This run uses OFFLINE analysis: fetch_url, clone_repo and mb_lookup are disabled. "
        "Do not call them, even if earlier generic examples mention them.\n"
    )
    analysis = ""
    if "analyze_sample" in allowed:
        analysis = (
            "analyze_sample operations: " + ", ".join(sorted(ANALYSIS_OPTIONS)) + ".\n"
            "strings/strings_utf16 options: min_length (default 6, range 1..4096), offset, limit. "
            "grep options: pattern (extended regex, case-insensitive), offset, limit; "
            "returns matching text fragments, including from binary files. "
            "offset/limit count characters in command output, not bytes in the sample; "
            "pages contain at most 4000 characters. Use the returned next_offset; EOF means stop. "
            "Unsupported options are errors; output/output_file do not create files. "
            "If a tool or rules are unavailable, record that limitation and use another operation; "
            "do not retry unchanged unavailable tools.\n"
        )
    examples = []
    for tool in sorted(allowed):
        fields = (ROLE_SPEC_EXAMPLES[role][tool]
                  if tool in {"update_spec", "append_spec"} else EXAMPLES[tool])
        examples.append(json.dumps({"tool": tool, **fields}))
    return (
        "\n\nAUTHORITATIVE TOOL CONTRACT\n"
        "Emit one or more <tool_call>JSON_OBJECT</tool_call> blocks. Each object uses the flat, named fields below. "
        "Do not put fields inside arguments/parameters, and do not emit Python calls. Examples show syntax, not sample findings; "
        "replace example values with the actual run facts.\n"
        + availability + analysis +
        "update_spec and append_spec must use fields writable by your role; controller-owned facts are read-only.\n"
        "read_spec with no path reads the shared state; path selects a dotted subtree. "
        "offset/limit optionally page list items or dictionary keys. read_file offset/limit count characters. "
        "Truncation is explicitly marked; request a narrower path or the next page when needed.\n"
        "read_file is limited to the run workspace. Only analyze_sample can also inspect the pinned "
        "original sample outside the workspace; use strings/grep for that sample.\n"
        "write_file requires path and content (a string; JSON-encode report objects). "
        "finish requires a non-empty summary and does not create or repair outputs.\n"
        + "\n".join(examples)
    )
