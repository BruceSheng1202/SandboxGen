#!/usr/bin/env bash
# =============================================================================
# run_samples.sh
# Runs the SandboxGEN orchestrator on every sample in a directory, one at a
# time. Results land in workspace/results/<sample>/
#
# Usage:
#   ./run_samples.sh [samples_dir]
#   (defaults to ./all_samples relative to this script)
#
# Environment:
#   MAX_ATTEMPTS=N                     pass --max-attempts N (default 1)
#   SANDBOXGEN_ALLOW_NETWORK_STORAGE=1 pass --allow-network-storage (only for
#                                      harmless canaries / scoring on NFS)
#   PYTHON=...                         interpreter (default python3)
# =============================================================================

SANDBOXGEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="${1:-$SANDBOXGEN_DIR/all_samples}"
WORKSPACE_BASE="$SANDBOXGEN_DIR/workspace/results"
PYTHON="${PYTHON:-python3}"
ORCHESTRATOR="$SANDBOXGEN_DIR/orchestrator.py"
LLM_CONFIG="$SANDBOXGEN_DIR/config/llm.yaml"
CAPE_CONFIG="$SANDBOXGEN_DIR/config/cape.yaml"
LOG_FILE="$SANDBOXGEN_DIR/run_samples.log"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-1}"
EXTRA_ARGS=()
if [[ "${SANDBOXGEN_ALLOW_NETWORK_STORAGE:-0}" == "1" ]]; then
    EXTRA_ARGS+=(--allow-network-storage)
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERR]${NC}   $*" | tee -a "$LOG_FILE"; }

# ---------- preflight ---------------------------------------------------------
if [[ ! -f "$ORCHESTRATOR" ]]; then
    echo "orchestrator.py not found at $ORCHESTRATOR" >&2
    exit 1
fi

if [[ ! -d "$SAMPLES_DIR" ]]; then
    echo "Samples directory not found: $SAMPLES_DIR" >&2
    exit 1
fi

for cfg in "$LLM_CONFIG" "$CAPE_CONFIG"; do
    if [[ ! -f "$cfg" ]]; then
        echo "Config not found: $cfg" >&2
        echo "Copy the template first: cp ${cfg}.example ${cfg}  (then fill in your keys)" >&2
        exit 1
    fi
done

mkdir -p "$WORKSPACE_BASE"
true > "$LOG_FILE"

log "Samples dir  : $SAMPLES_DIR"
log "Workspace    : $WORKSPACE_BASE"
log "Orchestrator : $ORCHESTRATOR"
log "LLM config   : $LLM_CONFIG"
log "CAPE config  : $CAPE_CONFIG"
log "Log file     : $LOG_FILE"
log "Max attempts : $MAX_ATTEMPTS"

# ---------- counters ----------------------------------------------------------
total=0; succeeded=0; failed=0; skipped=0

# ---------- main loop ---------------------------------------------------------
for sample in "$SAMPLES_DIR"/*; do
    # Skip non-files (e.g. download.log, .bad files)
    [[ -f "$sample" ]] || continue
    filename=$(basename "$sample")

    # Skip log and bad files
    [[ "$filename" == "download.log" ]] && continue
    [[ "$filename" == *.bad ]]          && continue

    total=$((total + 1))
    workspace="$WORKSPACE_BASE/$filename"

    # Skip only if the controller signed the run off. success.json is
    # written by orchestrator._finalise() for a run whose report was
    # sha256-verified and whose final report passed validation; a failed
    # Analyst can still leave analysis_report.json behind, so that file is
    # not the criterion (round-1 INT-07, round-2 SG-INT-01).
    if [[ -f "$workspace/success.json" ]] || compgen -G "$workspace/attempt_*/success.json" > /dev/null; then
        ok "[$filename] Already processed — skipping"
        skipped=$((skipped + 1))
        continue
    fi

    mkdir -p "$workspace"
    log "[$filename] Starting ($total) ..."

    cd "$SANDBOXGEN_DIR" && "$PYTHON" "$ORCHESTRATOR" \
        --binary "$sample" \
        --workspace "workspace/results/$filename" \
        --llm-config "$LLM_CONFIG" \
        --cape-config "$CAPE_CONFIG" \
        --max-attempts "$MAX_ATTEMPTS" \
        "${EXTRA_ARGS[@]}" \
        >> "$LOG_FILE" 2>&1

    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        ok "[$filename] Completed successfully ✓"
        succeeded=$((succeeded + 1))
    else
        err "[$filename] Failed with exit code $exit_code"
        failed=$((failed + 1))
        echo "FAILED  $filename  exit=$exit_code" >> "$LOG_FILE"
    fi

    echo "---" >> "$LOG_FILE"
done

# ---------- summary -----------------------------------------------------------
echo ""
echo "============================================="
log "Total samples    : $total"
log "Succeeded        : $succeeded"
log "Skipped (done)   : $skipped"
log "Failed           : $failed"
echo "============================================="

if [[ $failed -gt 0 ]]; then
    exit 1
fi
exit 0
