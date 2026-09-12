"""Shared backend facts and validation of the model's submission plan."""


def is_qemu(client):
    return getattr(getattr(client, "cfg", None), "mode", None) == "qemu"


def publish_backend_facts(spec, client):
    capabilities = getattr(client, "capabilities", None)
    if callable(capabilities):
        spec.set("cape_submission.backend_capabilities", capabilities(), actor="controller")
    spec.set("cape_submission.available_machines", client.list_machines(), actor="controller")


def submission_problems(spec, client, sample_path):
    """No mutations, staging or model decisions are made by this check."""
    errors = []
    existing_error = spec.get("cape_submission.error")
    if existing_error:
        errors.append("Architect reported an unresolved error: " + str(existing_error))
    options = {key: spec.get("cape_submission." + key) for key in (
        "package", "platform", "machine", "timeout", "options", "memory",
        "enforce_timeout", "tags", "priority")}
    for field in ("package", "platform"):
        if not isinstance(options[field], str) or not options[field].strip():
            errors.append(f"cape_submission.{field} must be configured")
    timeout = options["timeout"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        errors.append("cape_submission.timeout must be a positive integer")
    target = spec.get("sample.os_target")
    if target in ("linux", "windows", "android", "macos") and options["platform"] != target:
        errors.append(f"submission platform {options['platform']!r} does not match sample target {target!r}")
    if is_qemu(client) and not options["machine"]:
        errors.append("cape_submission.machine must select an available compatible QEMU guest")
    if options["machine"]:
        machines = spec.get("cape_submission.available_machines") or []
        matches = [m for m in machines if options["machine"] in (m.get("name"), m.get("label"))]
        if machines and not matches:
            errors.append("selected machine is not in the backend machine list")
        elif matches and all(m.get("platform") not in (None, "", options["platform"]) for m in matches):
            errors.append("selected machine platform is incompatible with the submission")
    validate = getattr(client, "validate_submission", None)
    if callable(validate) and sample_path:
        try:
            validate(str(sample_path), options)
        except (ValueError, OSError, TypeError) as exc:
            errors.append(str(exc))
    return errors
