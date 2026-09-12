# Linux/Windows consistency update — 2026-09-12

This update fixes the framework inconsistencies identified in the Linux/Windows audit. It changes active source and prompts; historical experiment snapshots and reports keep their original meaning. It does not establish new model accuracy or completion rates.

## Submission contract

The controller supplies backend capabilities and available machines before Scout analysis. QEMU supports little-endian i386/x86_64 ELF, `.sh` via `/bin/sh`, `.py` via `/usr/bin/python3`, and `.pl` via `/usr/bin/perl` in its Linux guest. ELF uses `package=elf`, Python uses `python`, and shell/Perl use `generic`. Availability of an interpreter or ELF ABI does not guarantee a sample's required libraries and dependencies are installed.

Windows is listed only when its golden image and saved state are configured. Supported Windows packages are x86/x64 `exe` and `dll`; DLL submission requires an explicit compatible export name or ordinal. `DllMain` is not accepted as a rundll32 entry. Loading a DLL does not prove successful execution of its selected export.

Both platforms reject explicit package/platform/machine mismatches before staging a sample. Header checks reject incompatible architectures and malformed bounded headers; they do not validate every executable section or guarantee runtime success. QEMU routes are `drop`/`none`, with actual isolated routing recorded as `drop`.

An Architect stage must finish with a valid package, platform, timeout and compatible machine, and without an unresolved `cape_submission.error`. Model completion alone is insufficient. Architect-driven recovery also validates the revised configuration before retrying.

## Actual settings and recovery

Submission acknowledgements record requested/effective settings and unsupported options in controller-owned `cape_submission.actual` and `sandbox.actual`. RAM, CPUs, interpreter, monitors, routing and timeout behavior come from deployment settings. Scout's desired environment, resource and monitor configuration is retained as a proposal and is not automatically provisioned. Models cannot write the actual-settings fields.

QEMU health checks describe configured-artifact readiness; each task separately checks guest startup. QEMU boots disposable guests per submission and does not use CAPE Docker service checks, libvirt recovery or shared legacy VM leases. There is no background CAPE processor to recover a missing synchronous QEMU report. Null timeout/options values are handled during recovery, and QEMU retries do not invent CAPE human simulation or sleep skipping.

Linux currently observes the traced process group until exit or timeout; Windows observes the full configured window. Unsupported requests to change these semantics are reported. No VM image rebuild is required for this source update: the existing Linux agent already exports strace and run metadata consumed by the updated host collector.

## Evidence semantics

New Linux reports have `sandboxgen.evidence_schema_version=2`. Execution validity requires an observed successful exec of the submitted path, or of the selected interpreter with that script path, plus run metadata without explicit launch/collection errors. A nonzero exit after successful startup is allowed. A PID, failed exec or timeout alone is insufficient. Old Linux reports remain readable but cannot pass this new execution-validity gate without the required evidence.

Linux summaries distinguish `file_write_attempted`, `file_opened_for_write`, and positive-byte `file_written`. `executed` includes only successful exec calls. `behavior.syscall_events` retains outcomes and errno, up to 2,000 entries, with a truncation count. These summaries are not exhaustive forensic evidence: unsupported syscall forms, truncated strings, mmap writes and untraced activity may be absent.

TCP, UDP and unknown socket connections are separate. A successful UDP connect does not establish a TCP connection. Packet-capture data is labeled guest-wide and unattributed, and modified-file candidates are also guest-wide. Neither channel alone proves sample ownership. The Analyst instructions reflect these limits.

## Validation scope

`tests/test_platform_consistency.py` covers invalid startup, headers, request mismatches, option acknowledgements, syscall outcomes, socket protocols, backend-specific checks/recovery, configuration ownership and pipeline gating. These are offline regression tests using inert headers, synthetic traces and mocked VM/API boundaries. The existing full suite is also run. Real Linux/Windows guest canaries and same-sample model comparisons are separate validation steps; this update does not claim those were run.
