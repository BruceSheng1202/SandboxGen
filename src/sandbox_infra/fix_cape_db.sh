#!/bin/bash
# fix_cape_db.sh — Fix CAPEv2 database issues after container restart
# Handles: missing migrations, missing user, missing token

# INF-11 fix: fail on unset variables and unguarded command failures.
set -euo pipefail

CAPE_CONTAINER="cape"
VENV="${CAPE_VENV:?Set CAPE_VENV to the virtualenv path inside the CAPEv2 container}"
PYTHON="$VENV/bin/python"
MANAGE="/opt/CAPEv2/web/manage.py"

# INF-06 fix: cape.yaml lives one directory up from this script
# (sandbox_infra/../config/cape.yaml), not at the previously hardcoded
# deployment-specific absolute path — which may not exist, so the token
# update below used to silently no-op against a path that isn't the real
# config.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPE_YAML="$SCRIPT_DIR/../config/cape.yaml"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[DB]${NC} $1"; }
warn() { echo -e "${YELLOW}[DB]${NC} $1"; }
fail() { echo -e "${RED}[DB]${NC} $1"; exit 1; }

echo ""
echo "================================================"
echo "  CAPEv2 Database Fix"
echo "================================================"
echo ""

# ── Step 1: Run migrations ────────────────────────────────────────────
log "Running database migrations..."
docker exec "$CAPE_CONTAINER" bash -c \
    "su cape -c 'cd /opt/CAPEv2/web && $PYTHON $MANAGE migrate' 2>&1 | tail -3"

# ── Step 2: Create superuser if missing ──────────────────────────────
log "Checking superuser..."
USER_EXISTS=$(docker exec "$CAPE_CONTAINER" bash -c \
    "su cape -c 'cd /opt/CAPEv2/web && $PYTHON $MANAGE shell -c \
    \"from django.contrib.auth.models import User; print(User.objects.filter(username=\\\"cape\\\").count())\"' \
    2>&1 | tail -1")

if [ "$USER_EXISTS" = "0" ]; then
    warn "User not found. Creating superuser..."
    docker exec "$CAPE_CONTAINER" bash -c \
        "su cape -c 'cd /opt/CAPEv2/web && $PYTHON $MANAGE createsuperuser \
        --username cape --email cape@cape.local --noinput' 2>&1"

    # INF-06 fix: no hardcoded "cape"/"cape" superuser credential. Generate
    # a random password inside the container and have Django's shell read
    # it directly from disk (open(...).read()) — this avoids ever having
    # to interpolate the secret value through nested bash/SQL quoting
    # layers, and it's never printed or logged.
    docker exec "$CAPE_CONTAINER" bash -c \
        "ADMIN_PASS_FILE=/opt/CAPEv2/.web_admin_password; \
         if [ ! -f \"\$ADMIN_PASS_FILE\" ]; then \
             head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24 > \"\$ADMIN_PASS_FILE\"; \
             chmod 600 \"\$ADMIN_PASS_FILE\"; \
         fi"
    docker exec "$CAPE_CONTAINER" bash -c \
        "su cape -c 'cd /opt/CAPEv2/web && $PYTHON $MANAGE shell -c \
        \"from django.contrib.auth.models import User; \
        u=User.objects.get(username=\\\"cape\\\"); \
        u.set_password(open(\\\"/opt/CAPEv2/.web_admin_password\\\").read().strip()); \
        u.save()\"' 2>&1"
    log "Superuser created. Password written to /opt/CAPEv2/.web_admin_password inside the container (not printed)."
else
    log "Superuser exists."
fi

# ── Step 3: Get or create API token ──────────────────────────────────
log "Getting API token..."
NEW_TOKEN=$(docker exec "$CAPE_CONTAINER" bash -c \
    "su cape -c 'cd /opt/CAPEv2/web && $PYTHON $MANAGE shell -c \
    \"from django.contrib.auth.models import User; \
    from rest_framework.authtoken.models import Token; \
    u=User.objects.get(username=\\\"cape\\\"); \
    t,_=Token.objects.get_or_create(user=u); \
    print(t.key)\"' 2>&1 | tail -1")

if [ -z "$NEW_TOKEN" ] || echo "$NEW_TOKEN" | grep -q "Error\|Exception"; then
    fail "Failed to get API token: $NEW_TOKEN"
fi

log "Token retrieved (not printed — written directly to cape.yaml)."

# ── Step 4: Update cape.yaml ──────────────────────────────────────────
if [ -f "$CAPE_YAML" ]; then
    sed -i "s/token: .*/token: $NEW_TOKEN/" "$CAPE_YAML"
    log "Updated $CAPE_YAML"
else
    fail "cape.yaml not found at $CAPE_YAML — token NOT written. Fix CAPE_YAML path and re-run."
fi

# ── Step 5: Restart cape-web service ─────────────────────────────────
log "Restarting cape-web service..."
docker exec "$CAPE_CONTAINER" bash -c \
    "systemctl restart cape-web.service && sleep 5 && \
    systemctl is-active cape-web.service 2>&1" || true

# ── Step 6: Verify API is working ────────────────────────────────────
log "Verifying API..."
RESPONSE=$(curl -s http://localhost:8001/apiv2/tasks/list/ \
    -H "Authorization: Token $NEW_TOKEN" | head -20 || true)

if echo "$RESPONSE" | grep -q '"data"'; then
    log "API working correctly."
else
    fail "API still not working: $RESPONSE"
fi

echo ""
echo "================================================"
echo "  Database Fix Complete"
echo "================================================"
echo "  Token: (written to $CAPE_YAML, not printed)"
echo "  API:   http://localhost:8001"
echo ""
log "Done. Run ./run_windows_samples.sh to start analysis."
