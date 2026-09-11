#!/usr/bin/env bash
# =============================================================================
# download_samples.sh
# Crawls all malware family folders, reads their JSON metadata, and downloads
# each sample into a single centralized folder via the MalwareBazaar API.
# Uses python3 + pyzipper to extract AES-encrypted ZIPs.
#
# Requires the MALWAREBAZAAR_API_KEY environment variable to be set:
#   export MALWAREBAZAAR_API_KEY=<your key>
#
# Usage:
#   ./download_samples.sh [samples_dir] [output_dir]
# =============================================================================

# ---------- config ------------------------------------------------------------
SAMPLES_DIR="${1:-$HOME/SandboxGEN/linux_samples}"
OUTPUT_DIR="${2:-$HOME/SandboxGEN/all_samples}"
LOG_FILE="$OUTPUT_DIR/download.log"
API_KEY="${MALWAREBAZAAR_API_KEY:?Set MALWAREBAZAAR_API_KEY before running this script}"
API_URL="https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD="infected"
MAX_RETRIES=3
DELAY_BETWEEN=1
# -----------------------------------------------------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERR]${NC}   $*" | tee -a "$LOG_FILE"; }

# ---------- preflight ---------------------------------------------------------
for cmd in jq curl sha256sum xxd python3; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "$cmd is required but not installed." >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
true > "$LOG_FILE"

log "Source dir : $SAMPLES_DIR"
log "Output dir : $OUTPUT_DIR"
log "API URL    : $API_URL"
log "Log file   : $LOG_FILE"

# ---------- counters ----------------------------------------------------------
total=0; downloaded=0; skipped=0; failed=0

# ---------- main loop ---------------------------------------------------------
for family_dir in "$SAMPLES_DIR"/*/; do
    [[ -d "$family_dir" ]] || continue

    family=$(basename "$family_dir")
    json_file=$(find "$family_dir" -maxdepth 1 -name "*.json" 2>/dev/null | head -1)

    if [[ -z "$json_file" ]]; then
        warn "[$family] No JSON file found — skipping"
        continue
    fi

    sha256=$(jq -r '.sha256 // empty' "$json_file")
    family_name=$(jq -r '.malware_family // empty' "$json_file")
    [[ -z "$family_name" ]] && family_name="$family"

    if [[ -z "$sha256" ]]; then
        warn "[$family_name] Missing sha256 — skipping"
        continue
    fi

    # DATA-06 fix: reject anything that isn't exactly 64 hex chars before
    # it's used in a path, form field, or (further below) passed to the
    # embedded Python extractor — malformed/malicious JSON metadata must
    # not be able to inject into any of those.
    if ! [[ "$sha256" =~ ^[a-f0-9]{64}$ ]]; then
        err "[$family_name] Invalid sha256 format in JSON — skipping: $sha256"
        continue
    fi

    dest="$OUTPUT_DIR/$sha256"
    total=$((total + 1))

    if [[ -f "$dest" ]]; then
        ok "[$family_name] Already exists — skipping"
        skipped=$((skipped + 1))
        continue
    fi

    log "[$family_name] Downloading ${sha256:0:16}..."

    success=false
    for attempt in $(seq 1 $MAX_RETRIES); do
        zip_tmp=$(mktemp /tmp/malbazaar_XXXXXX.zip)

        http_code=$(curl --silent \
            --request POST \
            --header "Auth-Key: $API_KEY" \
            --data "query=get_file&sha256_hash=$sha256" \
            --output "$zip_tmp" \
            --write-out "%{http_code}" \
            --connect-timeout 15 \
            --max-time 120 \
            --max-filesize 209715200 \
            "$API_URL" 2>/dev/null) || true

        if [[ "$http_code" != "200" ]]; then
            warn "  Attempt $attempt/$MAX_RETRIES — HTTP $http_code"
            rm -f "$zip_tmp"
            sleep $((attempt * 2))
            continue
        fi

        # Check ZIP magic bytes PK\x03\x04
        magic=$(xxd -l 4 -p "$zip_tmp" 2>/dev/null || true)
        if [[ "$magic" != "504b0304" ]]; then
            body=$(cat "$zip_tmp" 2>/dev/null || true)
            err "  Attempt $attempt/$MAX_RETRIES — Not a ZIP. Response: $body"
            rm -f "$zip_tmp"
            sleep $((attempt * 2))
            continue
        fi

        # Extract using python3 + pyzipper (handles AES-256 encryption).
        # DATA-06 fix: zip_tmp/dest/password are passed as argv, not
        # interpolated into the heredoc source (which is now single-quote
        # delimited, so bash performs no substitution into it at all) —
        # malformed metadata can no longer inject Python. Also reject
        # anything that isn't exactly one ZIP member.
        extracted=$(python3 - "$zip_tmp" "$dest" "$ZIP_PASSWORD" <<'PYEOF'
import sys, io, pyzipper

zip_path, dest_path, zip_password = sys.argv[1], sys.argv[2], sys.argv[3]

with open(zip_path, "rb") as f:
    data = f.read()

try:
    MAX_MEMBER_BYTES = 200 * 1024 * 1024  # 200MB
    MAX_COMPRESSION_RATIO = 100  # DATA-03 zip-bomb defense

    with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
        zf.setpassword(zip_password.encode())
        names = zf.namelist()
        if not names:
            print("ERROR: ZIP is empty", file=sys.stderr)
            sys.exit(1)
        if len(names) != 1:
            print(f"ERROR: expected exactly 1 member, found {len(names)}", file=sys.stderr)
            sys.exit(1)
        info = zf.getinfo(names[0])
        if info.file_size > MAX_MEMBER_BYTES:
            print(f"ERROR: member size {info.file_size} exceeds "
                  f"{MAX_MEMBER_BYTES} byte cap", file=sys.stderr)
            sys.exit(1)
        ratio = info.file_size / max(info.compress_size, 1)
        if ratio > MAX_COMPRESSION_RATIO:
            print(f"ERROR: compression ratio {ratio:.1f}:1 exceeds "
                  f"{MAX_COMPRESSION_RATIO}:1 cap (likely zip bomb)", file=sys.stderr)
            sys.exit(1)
        raw = zf.read(names[0])

    with open(dest_path, "wb") as out:
        out.write(raw)
    print("OK")
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
        )

        rm -f "$zip_tmp"

        if [[ "$extracted" == "OK" ]]; then
            success=true
            break
        else
            err "  Attempt $attempt/$MAX_RETRIES — extraction failed"
            sleep $((attempt * 2))
        fi
    done

    if [[ "$success" == "true" ]]; then
        actual_sha=$(sha256sum "$dest" | awk '{print $1}')
        if [[ "$actual_sha" == "$sha256" ]]; then
            size=$(stat -c%s "$dest" 2>/dev/null || stat -f%z "$dest")
            ok "[$family_name] Saved & verified ✓  ($size bytes)"
            downloaded=$((downloaded + 1))
            echo "OK        $sha256  $family_name" >> "$LOG_FILE"
        else
            err "[$family_name] SHA256 MISMATCH — expected $sha256, got $actual_sha"
            mv "$dest" "$dest.bad"
            failed=$((failed + 1))
            echo "MISMATCH  $sha256  $family_name" >> "$LOG_FILE"
        fi
    else
        err "[$family_name] Download failed after $MAX_RETRIES attempts"
        failed=$((failed + 1))
        echo "FAILED    $sha256  $family_name" >> "$LOG_FILE"
    fi

    sleep "$DELAY_BETWEEN"
done

# ---------- summary -----------------------------------------------------------
echo ""
echo "============================================="
log "Total processed  : $total"
log "Downloaded       : $downloaded"
log "Skipped (exists) : $skipped"
log "Failed           : $failed"
echo "============================================="

if [[ $failed -gt 0 ]]; then
    exit 1
fi
exit 0
