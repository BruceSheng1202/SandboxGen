# Configuration and complete runs

Run all commands below from the repository root. Only example paths belong in version control; keep actual configuration, samples, and outputs local.

## Configuration files

`src/config/llm.yaml.example` is a usable single-model configuration with GLM-5.2, temperature 0, seed 42, up to 4 attempts per logical request, a 120–300 second read timeout, and a 1200 second retry admission budget. Change `backend`, `model`, and `base_url` for other services. Seed support depends on the provider; temperature zero does not guarantee identical results across runs.

You can set `api_key` in an ignored local YAML file with mode 0600. An empty value falls back to `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. The production shell wrapper forwards these exported environment variables and `MALWAREBAZAAR_API_KEY` by name, keeping credential values out of Podman's command-line arguments. It does not load `.env` files automatically. An explicit YAML key takes precedence over an environment variable; an old YAML value can override newly exported credentials.

The backend template uses `mode: qemu`. `qemu_vm_dir` contains the golden disks and Windows RAM state; `qemu_task_dir` is a separate local task directory for each run. Use absolute paths without spaces, `~`, `$HOME`, or YAML quotes: the wrapper's simple field reader does not expand environment variables or handle paths containing spaces. Keep image assets, samples, and disposable task data in separate directories.

Windows disk/state files are optional, but current preflight checks still require the Linux golden disk. `qemu_win_smp` must match the Windows build settings. The reference state uses 8 vCPUs, 4096 MiB of RAM, a Nehalem CPU, and a fixed device layout.

## A benign complete-run example

First build the container images and Linux guest using the [QEMU guide](../src/sandbox_infra/qemu/README.md). This complete workflow calls the model API. For offline validation only, run the pytest command in the README.

```bash
umask 077
# Use LOCAL disk, not NFS/CIFS. This example uses /var/tmp.
run_dir=$(mktemp -d /var/tmp/sandboxgen-run.XXXXXX)
mkdir -p "$run_dir/samples" "$run_dir/tasks/ws"
printf '#!/bin/sh
printf "sandboxgen benign canary\n"
' > "$run_dir/samples/canary.sh"
chmod 700 "$run_dir/samples/canary.sh"
```

Edit `src/config/cape.yaml` and set `qemu_task_dir` to the expanded absolute path of `$run_dir/tasks` created above. Keep the model configuration in `src/config/llm.yaml`, then run:

```bash
SANDBOXGEN_SAMPLES_DIR="$run_dir/samples"   bash src/sandbox_infra/run_pipeline.sh   --binary "$run_dir/samples/canary.sh"   --workspace "$run_dir/tasks/ws"
```

Use the same directory constraints for real samples and set `SANDBOXGEN_LIVE=1`. On shared clusters, run on an allocated compute node. The production wrapper mounts the source, configuration, sample directory, VM directory, and task directory; other host paths do not become visible inside the container automatically.

`CAPE_CONFIG` and `LLM_CONFIG` can select configuration paths, but those paths must lie within existing container mounts. Local `src/config/` files are the simplest option. `SANDBOXGEN_PODMAN_SOCK` can select a rootless Podman socket, and `SANDBOXGEN_IMAGE_STORE` can select a directory of locally exported container tar files. Normally, build the images first using the guide instead of relying on legacy default paths for automatic image restoration.

The API retry setting `max_attempts` differs from CLI `--max-attempts`. The CLI option limits repetitions of the entire pipeline and defaults to 1. Increasing full-run repetitions does not change the retry limit for an individual HTTP request.

## Common failures

| Symptom | What to check |
|---|---|
| Missing credentials or authentication failure | Check YAML precedence inside the container and whether environment variables were exported. Do not paste credentials into an issue. |
| File not found | Check absolute paths, wrapper mounts, and directory permissions. Do not use unexpanded environment variables. |
| `golden image ... CHANGED` | Compare against the hash from a trusted build. Do not overwrite the `.sha256` file to hide a change. |
| PE sample rejected | Check for matching Windows disk/state files, the EXE/DLL type, architecture, and a DLL export that satisfies the calling contract. |
| `protocol_stalled` | Inspect tool formatting and correction attempts in the local trace. This is a failure after bounded recovery, not a successful run. |
| No network behavior observed | The guest network is isolated. Missing observations do not prove that the sample lacks that capability. |
| Unexpected termination | Inspect terminal status and the workspace. SIGKILL and node failures prevent shell traps from running; leftover private data may need cleanup. |

Validation and diagnostic outputs may contain sensitive information. Review them according to [SECURITY.md](../SECURITY.md) before uploading.
