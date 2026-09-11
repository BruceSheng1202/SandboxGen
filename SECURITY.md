# Isolation and sensitive data

This project analyzes untrusted files. The current production entry point is `src/sandbox_infra/run_pipeline.sh`. Its networked controller/harness uses a trusted Podman socket to create separate containers for static analysis and dynamic execution. Analysis containers do not inherit that socket. Dynamic samples run in a QEMU guest; the outer container uses `--network none`, and the guest uses isolated networking with controlled port forwarding to its agent.

These mechanisms reduce risk but do not guarantee that escape is impossible. The Podman socket controls the user's containers and belongs to the trusted control plane. Do not expose it to sample containers or the public internet. Running the orchestrator directly does not automatically configure the same isolation.

- Keep real credentials in ignored local configuration or a secret management system. Do not commit `.env`, actual YAML configuration, key files, or command histories. Passing environment variable names keeps credential values out of the startup command line; process environments and container configuration metadata still require access controls.
- Log redaction is not a complete privacy filter. Prompts, paths, extracted strings, request metadata, and reports may contain sensitive information. Do not upload raw traces to public issues.
- Model APIs receive analysis inputs and tool outputs and may incur charges. Provider connections are separate from the isolated guest network.
- The `analyst` guest account and password are public defaults for an isolated experimental VM, not maintainer credentials. Do not reuse them on hosts, networked services, or production accounts. The guest agent is not an authenticated public service. Saved RAM state is tied to the guest configuration; rebuild and validate it after changing the guest.
- If a golden-image hash is missing, preflight records the current file as the baseline. This does not authenticate the download source. Verify the source before recording a baseline; do not overwrite a baseline to bypass a mismatch.
- Normal cleanup and controlled exits remove intermediate run data. SIGKILL and host failures can prevent cleanup from running. Inspect and remove leftover private task directories as needed.
- Release checks cover files selected for publication and cannot undo a credential leak. If a leak occurs, revoke or rotate the credential at the provider and inspect history and caches.

Report security issues through the hosting platform's private security reporting channel when one is enabled. If no private channel exists, first send a contact request without vulnerability details or sensitive data. Public issues should include only a minimal synthetic reproduction, version information, and redacted errors. Do not attach real malicious payloads.
