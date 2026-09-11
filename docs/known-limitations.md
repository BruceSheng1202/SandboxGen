# Known limitations and preserved behavior

Release preparation preserves the reference version's functionality. The following issues remain documented; experimental reports and success statuses were not rewritten to conceal them.

1. **Tool protocol recovery can fail.** In reference batch R6, the Architect repeatedly produced invalid tool calls for `data_x86_64`. Normal correction and finalization did not recover the run. It ended with `protocol_stalled` before dynamic execution.
2. **Runtime prompts contain inconsistent backend descriptions.** The Architect's Windows-only wording conflicts with QEMU's Linux support, and the capability dictionary is Windows-focused. Model output has reflected this inconsistency. Prompts are functional inputs and remain unchanged in this release; this issue is not fixed. Future changes require separate regression validation.
3. **Linux syscall summaries do not reliably distinguish success from failure.** `file_written`, `executed`, and connection lists alone do not prove successful writes, execution, persistence, or connections. Socket types and other details may also be missing.
4. **Collection coverage and execution-health contracts differ across platforms.** Lists have length limits, and behavior originating from Windows services may be classified as background noise. Linux and Windows startup/execution health evidence is not fully aligned.
5. **Complete retention of raw material is not guaranteed.** Current cleanup and archival paths do not guarantee preservation of every strace, PCAP, temporary output, or file inferred by a model. Report fields do not establish that the underlying sensor data is available for review.
6. **The backend does not implement every CAPE feature.** Some shared prompts may suggest unsupported settings such as `human`, sleep skipping, or FakeNet. Check backend acknowledgements to determine which parameters actually took effect.
7. **Isolation, architecture, and dependencies limit behavioral coverage.** Downloaders, environment-specific payloads, and DLLs may not be fully triggered. A Windows ImageLoad event proves loading only.
8. **Report delivery does not establish accuracy.** Known issues include evidence misinterpretation, unsupported inferences, and mapping errors. Not all reports have undergone detailed semantic scoring.
9. **Source code alone cannot reproduce the full environment.** Original images, datasets, provider state, and reference containers are not distributed with the repository. Dependency locks describe the release validation environment, not a package-for-package copy of the old VMs or containers.
10. **Direct Python execution and the production wrapper provide different isolation.** Direct execution may use the legacy fork-based static parsing path. Passing offline tests does not validate the isolation configuration of a real deployment.
11. **External dependencies and installation media require maintenance.** Base OS images, guest software, and Windows evaluation terms change over time. Source tests and Python vulnerability scans do not cover VM/container operating systems or media that are not included.

Record future functional fixes as new versions and validate them with consistent inputs and acceptance rules. A sample's successful report delivery on an older version does not establish correct analysis on a newer version.
