# SandboxGEN

SandboxGEN is a research framework for malware analysis. Four model agents—Scout, Architect, Executor, and Analyst—perform static identification, execution planning, isolated dynamic analysis, and report preparation. The main deployment uses **rootless Podman + QEMU TCG** and supports Linux ELF files and scripts, Windows executables, and DLLs compatible with the rundll32 calling convention.

The controller validates report provenance and delivery. It does not guarantee that every analytical conclusion is correct.

This repository provides source code, configuration templates, offline tests, and general build scripts. API keys, malware samples, VM and container images, raw experimental reports, and cluster scheduling records are excluded.

## Capabilities and limitations

| Capability | Current implementation |
|---|---|
| Analysis workflow | Scout → Architect → Executor → Analyst. The controller validates sample SHA256, task associations, dynamic report provenance, and final report consistency. |
| Static analysis | The container entry point delegates `analyze_sample` operations to a separate analysis container without network access or a Podman socket. Available tools depend on the build environment. |
| Linux | ELF files and scripts run in an x86_64 guest. The interpreter, architecture, dynamic linker, and dependencies must match. |
| Windows | EXE files and DLLs. DLL analysis requires an explicit export name or ordinal compatible with rundll32. Loading a DLL does not prove that its export ran successfully. |
| Models | Anthropic, OpenAI, and OpenAI-compatible interfaces. The template uses the GLM-5.2 reference experiment settings. Provider capabilities differ. |
| Recovery | Bounded request retries, timeout budgets, tool protocol correction, and finalization. Recovery is not guaranteed. |
| Networking | QEMU analysis supports only the isolated `drop` and `none` routes. Arbitrary NAT, FakeNet, and INetSim configurations are not implemented. |
| CAPEv2 | REST/local adapters and legacy administration scripts remain available as a separate deployment path. Their capabilities do not describe the QEMU backend. |

There are no Android or macOS dynamic-analysis guests. CAPE memory dumps, sleep skipping, injection/extraction, and automatic VM creation from model proposals are not implemented. See [known limitations](docs/known-limitations.md) for evidence parsing and model interpretation issues.

## Run tests without an API key or VM

Use Python 3.12 and run these commands from the repository root:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/locks/dev.txt
.venv/bin/python -m pytest -q
.venv/bin/python src/orchestrator.py --help
.venv/bin/python tools/check_release.py
```

The release candidate passed **452 tests and 6 subtests** in a fresh environment installed from the lock file. The default tests use mocks and synthetic inputs; they do not call paid model APIs, download malware, or start VMs. Benign integration checks that require Podman or guests run separately; see [testing](docs/testing.md). See [dependencies](docs/dependencies.md) for the lock generation conditions and validation scope.

## Run a complete analysis

A complete run requires a Linux x86_64 host, rootless Podman, three container images, a prepared Linux golden disk, and access to a model API. Windows analysis also requires a Windows golden disk and matching RAM state.

1. Follow the [QEMU build and run guide](src/sandbox_infra/qemu/README.md) to prepare the images and guests. KVM is not required; TCG software emulation is slower.
2. Copy and edit the configuration templates with actual absolute paths and your own credentials. Configuration paths do not expand `$HOME` or `~`.

   ```bash
   cp src/config/cape.qemu.yaml.example src/config/cape.yaml
   cp src/config/llm.yaml.example src/config/llm.yaml
   chmod 600 src/config/cape.yaml src/config/llm.yaml
   ```

3. Create private sample and task directories on local disk for this run. `qemu_task_dir` must match the workspace's parent directory. Do not reuse a task directory that is still in use.
4. Use `src/sandbox_infra/run_pipeline.sh` as shown in the [configuration and run examples](docs/configuration.md). Validate the environment with a benign script before analyzing samples you are authorized to handle. Running `orchestrator.py` directly does not establish the same container isolation automatically.

The model API receives prompts, extracted features, tool outputs, and analysis evidence. Local traces may also contain sample content and paths. Configure the provider according to your data handling requirements. Samples execute in the guest; the controller's model connection is separate from the isolated guest network. See [isolation and credentials](SECURITY.md).

## Outputs and success criteria

The main files in a run's workspace are:

| File | Purpose |
|---|---|
| `analysis_report.json` | Standalone final analysis report. |
| `environment_spec.json` | Shared state between stages, including the embedded report. |
| `run_manifest.json` | Controller records of sample, task, route, and report hashes. |
| `success.json` | Marker written after controller validation passes. |
| `cape_report_<task_id>.json` | Dynamic evidence report with validated provenance. |
| `agent_trace.jsonl` / `workflow.json` | Per-round model and tool records, and workflow state. |
| `token_usage.json` | Known usage. Missing usage data or unconfigured rates prevent complete cost accounting. |

Report delivery requires a correctly associated dynamic task and agreement between the standalone and embedded reports. It does not establish that every behavioral conclusion is correct or that every payload was triggered.

## Reference validation

The production source used as the release baseline is the version evaluated in R6. Across three experiment batches, that version covered 32 samples and completed 31. The remaining sample failed to recover from an Architect tool-format error. Combining the latest results for 50 samples across four versions gives 49 reports, of which 48 pass strict delivery validation. **These figures are not analysis accuracy scores or results from testing all 50 samples on the current version.** See [evaluation scope](docs/evaluation.md).

Release preparation preserves the model prompts and production Python execution logic. Changes to configuration templates, documentation, dependencies, and legacy CAPE paths are documented separately. Paid model experiments and reference VM builds were not repeated. This repository alone cannot reconstruct the full environment and data used in the internal experiments.

## Repository guide

- [Source guide](src/README.md): core modules, the main entry point, and optional scripts.
- [Configuration](docs/configuration.md): models, backends, paths, and timeouts.
- [QEMU guide](src/sandbox_infra/qemu/README.md): containers and Linux/Windows guest builds.
- [Testing](docs/testing.md), [known limitations](docs/known-limitations.md), and [contributing](CONTRIBUTING.md).
- [Third-party components and license status](THIRD_PARTY.md): this snapshot adds no project-level open-source license.
