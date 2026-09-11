# Source guide

Start with the [repository README](../README.md) for installation and usage.

| Module | Responsibility |
|---|---|
| `orchestrator.py` | Four-stage scheduling, controller-owned facts, and final validation. |
| `agents/` | Scout, Architect, Executor, and Analyst. Their `SYSTEM_PROMPT` values are runtime inputs; changing them affects experimental behavior. |
| `core/agent_loop.py`, `tool_contracts.py` | Model loops, tool contracts, protocol parsing, and bounded recovery. |
| `core/report_validation.py` | Report fields, task IDs, and consistency between standalone and embedded reports. |
| `core/llm_backend.py` | Model adapters, request retries, timeouts, and usage accounting. |
| `core/run_context.py`, `spec_policy.py` | Sample/task/route/report ledgers and role permissions. |
| `core/qemu_backend.py` | Linux/Windows QEMU adapter. |
| `core/cape_client.py` | Backend selection and CAPEv2 REST/local adapters. |
| `sandbox_infra/run_pipeline.sh` | Current Podman container entry point. |
| `sandbox_infra/qemu/` | Guest builds, execution, and sensors. |
| `config/*.example` | Public configuration templates; users create actual configuration locally. |
| `preprocessing/` | Optional sample-source lookup and download tools. Configure service credentials before use. They are not part of the default tests. |
| `run_samples.sh` | Optional sequential batch driver, separate from the internal cluster scheduler used for frozen experiments. |

`sandbox_infra/amsa_*.sh`, `linux_*.sh`, `windows_*.sh`, `fix_cape_db.sh`, and `prepare_cape_guest.sh` support legacy CAPEv2/libvirt deployments. Their default VM names, private subnets, and container names describe an example topology. `amsa_start.sh` requires explicit `CAPE_WORK_DIR`, `CAPE_PGDATA_DIR`, `CAPE_ISO_DIR`, and `CAPE_VENV` values. `CAPE_VENV` is the virtual-environment path inside the CAPEv2 container and is also required by `windows_start.sh` and `fix_cape_db.sh`. These scripts are not used by the current QEMU entry point and were not validated in a real deployment during release preparation.

General unit tests and benign integration checks remain in `../tests/`. One-off diagnostic runners tied to private sample records, internal Slurm scripts, and data archives are excluded from the release.
