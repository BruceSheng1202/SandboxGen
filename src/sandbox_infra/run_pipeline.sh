#!/usr/bin/env bash
# =============================================================================
# run_pipeline.sh — run the SandboxGEN pipeline inside the harness container,
# behind the mandatory safety guardrails in preflight.sh.
#
# Scout analyze_sample operations run in isolated analysis sidecars, not on
# the host or in the networked harness. Detonation is delegated to sibling
# --network none containers via the host podman socket. The golden image dir
# (NFS, read-only) and the per-task dir (local scratch) are bind-mounted at
# IDENTICAL host paths so the -v paths the backend computes resolve on the
# host daemon.
#
# Guardrails (preflight.sh): golden-image integrity check, execution-node
# check, local-scratch task dir, and — here — a trap that wipes the per-task
# sample bytes on exit.
#
# Usage:  run_pipeline.sh <orchestrator args...>
#   canary:  run_pipeline.sh --binary /scratch/$USER/canary.elf --workspace ...
#   live:    SANDBOXGEN_LIVE=1 run_pipeline.sh --binary <real sample> --workspace ...
# Env: CAPE_CONFIG   (default $REPO/config/cape.yaml)
#      LLM_CONFIG    (default $REPO/config/llm.yaml)
#      HARNESS_IMAGE (default localhost/sandboxgen-harness:py312)
#      SANDBOXGEN_LIVE=1              strict real-malware guardrails
#      SANDBOXGEN_ALLOW_LOGIN_NODE=1  override the compute-node requirement
# =============================================================================
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"        # .../src
IMAGE="${HARNESS_IMAGE:-localhost/sandboxgen-harness:py312}"
CAPE_CONFIG="${CAPE_CONFIG:-$REPO/config/cape.yaml}"
LLM_CONFIG="${LLM_CONFIG:-$REPO/config/llm.yaml}"
SAMPLES_DIR="${SANDBOXGEN_SAMPLES_DIR:-/scratch/$USER/samples}"
# The harness container spawns sibling detonation containers over this socket.
# On a login node systemd --user provides it; under SLURM batch there is no
# systemd --user session, so allow an override and fall back to a transient
# `podman system service` (see the startup block below).
SOCK="${SANDBOXGEN_PODMAN_SOCK:-/run/user/$(id -u)/podman/podman.sock}"

[[ -f "$CAPE_CONFIG" ]] || { echo "cape config not found: $CAPE_CONFIG (cp cape.qemu.yaml.example)" >&2; exit 1; }

# ── mandatory safety preflight ────────────────────────────────────────────
# shellcheck source=preflight.sh
source "$REPO/sandbox_infra/preflight.sh"
preflight "$CAPE_CONFIG"

# resolve the dirs the container must see (identical host paths)
_yaml() { sed -nE "s/^${1}:[[:space:]]*([^#[:space:]]+).*/\1/p" "$CAPE_CONFIG" | head -1; }
VM_DIR="$(_yaml qemu_vm_dir)"      # golden images (NFS, read-only)
TASK_DIR="$(_yaml qemu_task_dir)"  # per-task overlays + sample bytes (local scratch)
: "${VM_DIR:?cape.yaml qemu_vm_dir}" ; : "${TASK_DIR:?cape.yaml qemu_task_dir}"
mkdir -p "$TASK_DIR"

# ── guardrail 3: wipe sample bytes on exit, always ─────────────────────────
# The backend deletes each sample after its run; this is the belt-and-braces
# for handled exits/signals. SIGKILL or node failure cannot run this trap;
# operators must verify and clean abandoned private task directories.
_cleanup() {
    find "$TASK_DIR" -type f \( -name sample -o -name 'overlay.qcow2' -o -name 'result.tar.gz' \) -delete 2>/dev/null || true
    find "$TASK_DIR" -mindepth 1 -maxdepth 1 -type d -empty -delete 2>/dev/null || true
}
trap _cleanup EXIT INT TERM

# Bring the podman API socket up. Prefer systemd --user (login node); if that
# does not produce the socket (SLURM batch has no --user session), launch a
# transient service ourselves at $SOCK and reap it on exit.
if [[ ! -S "$SOCK" ]]; then
    systemctl --user start podman.socket 2>/dev/null || true
fi
if [[ ! -S "$SOCK" ]]; then
    mkdir -p "$(dirname "$SOCK")"
    podman system service --time=0 "unix://$SOCK" >/dev/null 2>&1 &
    _PODMAN_SVC_PID=$!
    trap '[[ -n "${_PODMAN_SVC_PID:-}" ]] && kill "$_PODMAN_SVC_PID" 2>/dev/null; _cleanup' EXIT INT TERM
    for _ in $(seq 1 40); do [[ -S "$SOCK" ]] && break; sleep 0.25; done
fi
[[ -S "$SOCK" ]] || { echo "podman socket not found at $SOCK (started neither via systemd --user nor podman system service)" >&2; exit 1; }
[[ -x "$REPO/sandbox_infra/ensure_images.sh" ]] && "$REPO/sandbox_infra/ensure_images.sh" || true

# The detonation containers are spawned as siblings on the host (podman-remote
# over the socket) and keep their own --network none; the harness container has
# outbound network for the LLM only. The sample never runs in the harness
# container. See sandbox_infra/qemu/README.md.
SAMPLE_MOUNTS=()
if [[ -d "$SAMPLES_DIR" ]]; then
    SAMPLE_MOUNTS=(-v "$SAMPLES_DIR:$SAMPLES_DIR:ro")
fi
# Keep the former unset-means-empty behavior, overriding any image default,
# without putting credential values in the Podman process arguments.
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
export MALWAREBAZAAR_API_KEY="${MALWAREBAZAAR_API_KEY:-}"

podman run --rm -i \
    --security-opt label=disable \
    -v "$SOCK:/run/podman/podman.sock" \
    -v "$REPO:$REPO:ro" \
    -v "$VM_DIR:$VM_DIR:ro" \
    -v "$TASK_DIR:$TASK_DIR:rw" \
    "${SAMPLE_MOUNTS[@]}" \
    -w "$REPO" \
    -e "SANDBOXGEN_VM_DIR=$VM_DIR" \
    -e "SANDBOXGEN_ANALYZE_CONTAINER=1" \
    -e "SANDBOXGEN_ANALYZE_IMAGE=localhost/sandboxgen-analyze:py312" \
    -e ANTHROPIC_API_KEY \
    -e OPENAI_API_KEY \
    -e MALWAREBAZAAR_API_KEY \
    "$IMAGE" python3 orchestrator.py --cape-config "$CAPE_CONFIG" --llm-config "$LLM_CONFIG" "$@"
