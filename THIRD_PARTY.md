# Third-party components and license status

This snapshot adds no project-level open-source license and does not change ownership of the existing code. The repository owner must confirm code provenance and required permissions before choosing a project license. Dependency licenses do not determine the license for this project.

The repository contains project source code, tests, configuration examples, and build scripts. It does not include third-party program binaries, Windows ISOs, Sysmon executables, VM disks, or malware datasets.

| External component | Source and purpose |
|---|---|
| Python packages | Listed in `src/requirements.txt`, the lock files, and package distribution metadata. Each package retains its own license when installed. |
| Podman / QEMU | Host container runner and emulator, obtained from their respective projects or OS packages. |
| Ubuntu cloud image | Obtain and verify it from the [official Ubuntu cloud image directory](https://cloud-images.ubuntu.com/minimal/releases/noble/release/). |
| Windows installation media | Obtain it from the [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/). Check the applicable license, evaluation period, and architecture. |
| Sysmon | Obtain it separately from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). The build process uses its license-acceptance option. |
| CAPEv2 | Optional external deployment. Its implementation is not redistributed in this repository. |

`sysmonconfig.xml` is the project's collection configuration and contains no Sysmon executable. Provider-token strings in regression fixtures are fixed synthetic data used to test redaction, not real credentials.
