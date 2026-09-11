#!/usr/bin/env bash
# =============================================================================
# preflight.sh — mandatory safety checks before a SandboxGEN run.
#
# Sourced by run_pipeline.sh. Four guardrails the user approved before any real
# malware sample is downloaded or run:
#
#   1. Golden-image integrity   — verify the read-only golden matches its
#      recorded sha256 baseline. A changed golden means either corruption or
#      tampering; either way the run is refused rather than analysing on an
#      unknown base (guards against VM corruption).
#   2. Execution node           — heavy qemu belongs on a compute node, not a
#      shared login node. In live mode the run is refused on a login node
#      unless SANDBOXGEN_ALLOW_LOGIN_NODE=1 is set as an explicit override.
#   3. Sample-byte retention    — the caller installs a trap that wipes the
#      per-task sample bytes on exit (see run_pipeline.sh). preflight only
#      checks the task dir is on local scratch, never NFS (DATA-04).
#   4. Harness container        — the pipeline runs off the login node so
#      untrusted bytes are parsed in a container (run_pipeline.sh does this).
#
# Mode: SANDBOXGEN_LIVE=1 turns on the strict (real-malware) checks. Default
# (canary) mode still verifies the golden but only warns about the node.
# =============================================================================

_pf_die()  { echo "PREFLIGHT REFUSED: $*" >&2; exit 3; }
_pf_warn() { echo "PREFLIGHT WARNING: $*" >&2; }
_pf_ok()   { echo "preflight ok: $*"; }

# Read a scalar key from a simple cape.yaml (key: value, ignores comments).
_pf_yaml() { sed -nE "s/^${2}:[[:space:]]*([^#[:space:]]+).*/\1/p" "$1" | head -1; }

preflight() {
    local cape_cfg="$1"
    local live="${SANDBOXGEN_LIVE:-0}"

    # ── 1. golden integrity ────────────────────────────────────────────────
    local vm_dir golden task_dir win_golden
    vm_dir="$(_pf_yaml "$cape_cfg" qemu_vm_dir)"
    golden="$(_pf_yaml "$cape_cfg" qemu_golden)"
    task_dir="$(_pf_yaml "$cape_cfg" qemu_task_dir)"
    win_golden="$(_pf_yaml "$cape_cfg" qemu_win_golden)"
    [[ -n "$vm_dir" && -n "$golden" ]] || _pf_die "cape.yaml missing qemu_vm_dir/qemu_golden"

    _pf_verify_golden "$vm_dir/$golden" || return 1
    if [[ -n "$win_golden" && -f "$vm_dir/$win_golden" ]]; then
        _pf_verify_golden "$vm_dir/$win_golden" || return 1
    fi

    # ── 2. execution node ──────────────────────────────────────────────────
    local host; host="$(hostname)"
    if [[ "$host" == *login* && -z "${SLURM_JOB_ID:-}" ]]; then
        if [[ "$live" == "1" && "${SANDBOXGEN_ALLOW_LOGIN_NODE:-0}" != "1" ]]; then
            _pf_die "on login node $host — real-malware runs must use a compute node (salloc/srun). Override only if you understand the risk: SANDBOXGEN_ALLOW_LOGIN_NODE=1"
        fi
        _pf_warn "running on login node $host (fine for canaries; use a compute node for real samples)"
    else
        _pf_ok "execution node $host"
    fi

    # ── 3. task dir must be local scratch, never NFS ───────────────────────
    if [[ -n "$task_dir" ]]; then
        mkdir -p "$task_dir" 2>/dev/null || true
        local fstype; fstype="$(stat -f -c %T "$task_dir" 2>/dev/null || echo unknown)"
        case "$fstype" in
            nfs*|cifs*|smb*) _pf_die "qemu_task_dir $task_dir is on $fstype — sample bytes and overlays must stay on LOCAL disk (DATA-04). Point qemu_task_dir at /scratch." ;;
            *) _pf_ok "task dir $task_dir on local $fstype" ;;
        esac
    fi

    [[ "$live" == "1" ]] && _pf_ok "LIVE mode: strict guardrails active" \
                         || _pf_ok "canary mode"
    return 0
}

# Verify one golden image against vmstore/<name>.sha256; create the baseline on
# first sight (with a warning) so a fresh build is trusted once, then pinned.
_pf_verify_golden() {
    local img="$1" base="$1.sha256"
    [[ -f "$img" ]] || _pf_die "golden image not found: $img (build it first)"
    if [[ ! -f "$base" ]]; then
        sha256sum "$img" | awk '{print $1}' > "$base"
        _pf_warn "no integrity baseline for $(basename "$img") — recorded current hash as trusted. Re-run to enforce it."
        return 0
    fi
    local want have
    want="$(awk '{print $1}' "$base")"
    have="$(sha256sum "$img" | awk '{print $1}')"
    if [[ "$want" != "$have" ]]; then
        _pf_die "golden image $(basename "$img") sha256 CHANGED
    expected $want
    got      $have
  The base VM was modified since it was built — corruption or tampering. Refusing.
  Restore from ${img}.bak (if present) and re-verify before running."
    fi
    _pf_ok "golden $(basename "$img") integrity verified ($have)"
    return 0
}
