# Contributing and validation

Set up Python 3.12 using the repository README, then run `python -m pytest -q` and `python tools/check_release.py`. The tests do not require credentials, real samples, or VMs.

Review changes to runtime prompts, tool protocols, retries, and acceptance rules as functional changes. Verify them with regression cases that distinguish the old and new behavior. A report's existence does not establish that its conclusions are correct. Record the configuration, sample identity, code version, and terminal status of each new experiment separately; do not overwrite earlier results.

Before committing, run `git diff --check` and inspect all staged content. Do not rely solely on `.gitignore`: files that are already tracked can still enter a commit. Large files, VM images, datasets, credentials, and real traces do not belong in this source repository. The release tool checks candidate files by default; it does not replace history audits or credential rotation.

CI runs only offline checks, without provider credentials, untrusted sample execution, or VMs. When changing legacy CAPEv2 deployment scripts, describe how their validation scope differs from the current QEMU entry point.
