# Testing and release validation

## Default offline tests

Install `requirements/locks/dev.txt` in a Python 3.12 environment, then run from the repository root:

```bash
python -m pytest -q
python src/orchestrator.py --help
python tools/check_release.py
```

The original 447 tests and 6 subtests cover model request retries, tool protocols, report contracts, controller provenance checks, QEMU/Windows parsing, and synthetic pipelines. Release preparation added 5 release-check and shell regression tests, bringing the passing total to 452 tests and 6 subtests. The added tests cover forwarding credentials by environment variable name, mounting sample paths that contain spaces, and requiring explicit paths for legacy CAPE initialization. Wrapper regression tests create only a local Unix socket and a fake Podman executable; they do not start services, guests, or real containers. Sandboxes that restrict local sockets must allow this offline test to run.

CI uses read-only repository permissions and official checkout/setup-python actions pinned to commit SHAs. It installs the lock file and runs these checks without paid API credentials or real samples.

## Explicit benign integration checks

The following programs do not run automatically under pytest. They require prepared containers or VMs and save output to private local paths.

- `tests/qemu_canary_run.py`: a benign Linux script. Set `SANDBOXGEN_VM_DIR` and prepare the QEMU image and guest.
- `tests/windows_launch_canary.py --vm-dir ... --work ... --output ...`: synthetic EXEs that return and no-op x86/x64 DLLs. It neither downloads malware nor calls a model API.
- `tests/analysis_sidecar_canary.py --work ... --output ... --image-archive ...`: static sidecar validation using separate container storage. It requires an exported analyze container tar file.

Run these checks on a dedicated host or an allocated compute node. Use a separate task directory; do not use production image assets as a disposable workspace. Release preparation did not rebuild reference VMs or rerun real samples. New deployments still require these integration checks.

## Release-check scope

`tools/check_release.py` checks candidate files for credential patterns, named user directories, prohibited large files and runtime artifacts, text formatting, file links, Python syntax, shell syntax, JSON/YAML/XML configuration, and local Markdown links. In a Git repository, it checks all tracked and non-ignored files. Otherwise, it checks the source directory and skips local caches. Findings identify relative locations without printing credential values.

Synthetic test credentials and public defaults for isolated guest accounts serve explicit purposes and are not treated as real credentials. A scan cannot prove that future privacy leaks are impossible. Before committing, also check that real configuration is untracked and that author identity matches the intended disclosure scope.

Internal release preparation compared the candidate with the R6 source: production Python execution ASTs, excluding docstrings, and model prompts remain identical. Functional changes were limited to shell argument/credential forwarding and explicit legacy deployment paths needed for release. All original reference experiment directories were preserved.
