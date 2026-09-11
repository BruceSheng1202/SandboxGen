# QEMU TCG backend: build and run

Run commands in this guide from the [repository root](../../../README.md). The Linux x86_64 host needs rootless Podman, GNU coreutils, curl, and writable local disk. QEMU uses TCG inside a container; KVM and host root access are not required.

VM images, Windows ISOs, Sysmon executables, and samples are not included. Image builds access system package repositories, and Windows evaluation installations may need activation. Dynamic analysis uses isolated networking. TCG builds can take several hours.

## Build the three containers

```bash
podman build -t localhost/sandboxgen-qemu:alpine3.20 src/sandbox_infra/qemu
podman build -t localhost/sandboxgen-harness:py312 \
  -f src/sandbox_infra/Containerfile.harness .
podman build -t localhost/sandboxgen-analyze:py312 \
  -f src/sandbox_infra/Containerfile.analyze .
```

The harness installs from the Python dependency lock at the repository root; the analyze image adds tools to that local image. If a build fails, check repository availability and package names. Missing tools must not be treated as if they ran. Installation of `diec`, `tshark`, and third-party YARA rules is not guaranteed; the rules directory may be empty by default.

Use `podman save -o ...` to keep reusable images. The automatic image-restoration script accepts `SANDBOXGEN_IMAGE_STORE`. Public build definitions retain the reference QEMU baseline to preserve RAM-state compatibility. Base OS and package security maintenance requires separate checks; see [dependencies](../../../docs/dependencies.md).

## Linux golden disk

Choose a local directory with enough free space. The build script recreates the golden disk in that directory, so do not point it at reference assets that are still in use.

```bash
umask 077
vm_assets=/var/tmp/sandboxgen-vm-assets
mkdir -p "$vm_assets"
base_url=https://cloud-images.ubuntu.com/minimal/releases/noble/release
curl --fail --location "$base_url/ubuntu-24.04-minimal-cloudimg-amd64.img" \
  --output "$vm_assets/noble-minimal.img"
curl --fail --location "$base_url/SHA256SUMS" \
  --output "$vm_assets/SHA256SUMS"
# Compare the amd64.img entry in SHA256SUMS with this output; stop on mismatch.
sha256sum "$vm_assets/noble-minimal.img"
bash src/sandbox_infra/qemu/build_guest.sh "$vm_assets"
sha256sum "$vm_assets/golden.qcow2" > "$vm_assets/golden.qcow2.sha256"
```

The image and checksum file come from the [official Ubuntu directory](https://cloud-images.ubuntu.com/minimal/releases/noble/release/). For reproducible experiments, also record the download version, signature verification, image/container digests, and build configuration. The `release/` URL changes over time.

The script configures the guest agent, strace, and tcpdump, and saves an internal `agent_ready` snapshot. Current Linux dynamic runs **boot normally** from a new COW overlay rather than restoring that internal snapshot. Guest writes go to the overlay; the golden disk remains read-only.

## Windows golden disk and RAM state

Obtain an appropriate Windows 10 Enterprise Evaluation ISO and [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Place `Sysmon64.exe` in a private media directory and copy the collection configuration supplied here. The Windows installation template accepts the EULA, and Sysmon installation uses `-accepteula`. Confirm that you can accept the relevant terms before running the build.

```bash
mkdir -p "$vm_assets/win-media"
cp src/sandbox_infra/qemu/windows/sysmonconfig.xml "$vm_assets/win-media/"
# Place Sysmon64.exe in $vm_assets/win-media and obtain a licensed Windows ISO.
ISO=/absolute/path/to/windows-evaluation.iso \
OUT="$vm_assets" \
WORK=/var/tmp/sandboxgen-windows-build \
SANDBOXGEN_WIN_MEDIA="$vm_assets/win-media" \
  bash src/sandbox_infra/qemu/windows/build_windows_guest.sh
sha256sum "$vm_assets/win-golden.qcow2" > "$vm_assets/win-golden.qcow2.sha256"
sha256sum "$vm_assets/win-state.gz" > "$vm_assets/win-state.gz.sha256"
```

The main outputs, `win-golden.qcow2` and `win-state.gz`, must be kept together. The dynamic runner restores external RAM state onto a temporary overlay. CPU, QEMU version, device layout, memory, and vCPU count must match the build. Reference settings include a Nehalem CPU, 4096 MiB of RAM, 8 vCPUs, an IDE disk, and two e1000 NICs. Revalidate after updating QEMU, the guest, or the launcher; do not assume older state will still load.

`analyst` is a public experimental guest account, not a maintainer identity. The templates disable or adjust some Windows protections and background tasks to observe samples. Use them only in dedicated isolated guests, never on a workstation. Collection exclusions are also configured, so not every file operation is necessarily recorded.

## Configure and start an analysis

Create local YAML configuration following the [configuration guide](../../../docs/configuration.md). Set `qemu_vm_dir`, `qemu_golden`, and a separate `qemu_task_dir` for each run. Windows support also needs matching `qemu_win_golden`, `qemu_win_state`, and `qemu_win_smp` settings.

Use `src/sandbox_infra/run_pipeline.sh`. It delegates static analysis to a sidecar without network access or a Podman socket. Dynamic containers use `--network none`, a read-only root filesystem, dropped capabilities, and `no-new-privileges`; the guest uses isolated SLIRP networking. The controller has model connectivity and a Podman socket and is not an environment for executing untrusted samples.

Linux supports ELF files and scripts compatible with the guest. Windows supports `package=exe` and `package=dll`. DLLs require `function=<export_name_or_#ordinal>` and must follow the [rundll32 calling convention](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32). The backend does not guess entry points or support arbitrary function signatures. A model-selected export is not necessarily compatible with the loader.

Only `drop` and `none` routes are available. The backend does not provide CAPE memory dumps, sleep skipping, injection/extraction, FakeNet, or dynamic VM creation. Windows reports check execution health using actual sample processes and DLL ImageLoad events, among other evidence. Linux health contracts and option acknowledgements are not yet fully aligned with Windows.

## After the run

Inspect `run_manifest.json`, `success.json`, and the standalone report instead of relying on the last log line. Retain selected, redacted evidence. Workspaces, raw traces, screenshots, and intermediate archives do not belong in Git. Check cleanup after abnormal exits, especially node failures or SIGKILL, which prevent traps from running.

Source code and newly built images alone do not establish reproduction of the internal reference experiments. See [known limitations](../../../docs/known-limitations.md) and [benign validation procedures](../../../docs/testing.md).
