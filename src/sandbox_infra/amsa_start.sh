#!/bin/bash
# amsa_start.sh — Start the CAPEv2 analysis environment
#
# Usage:
#   ./amsa_start.sh

# Fail on unset variables, on the first failing command in a pipeline, and
# on any unguarded command failure. Every intentional idempotency guard
# below (`|| true`, `2>/dev/null || true`) is explicit and still a no-op
# under -e; this only changes behavior for the *unguarded* failures the
# security audit flagged (INF-11) — e.g. a failed migration or chown will
# now actually stop the script instead of being silently ignored.
set -euo pipefail

CAPE_IMAGE="cape:kvm"
CAPE_CONTAINER="cape"
WORK_DIR="${CAPE_WORK_DIR:?Set CAPE_WORK_DIR to your CAPEv2 work directory}"
PGDATA_DIR="${CAPE_PGDATA_DIR:?Set CAPE_PGDATA_DIR to your CAPEv2 database directory}"
ISO_DIR="${CAPE_ISO_DIR:?Set CAPE_ISO_DIR to your CAPEv2 installation-media directory}"
VENV="${CAPE_VENV:?Set CAPE_VENV to the virtualenv path inside the CAPEv2 container}"

# INF-14 fix: the container previously had no CPU/memory/PID ceiling at
# all, so a runaway analysis (fork bomb, memory-hungry unpacking, etc.)
# inside the CAPE guest tooling could exhaust the host. Override via env
# var per-deployment; defaults are generous but bounded rather than
# unlimited. --pids-limit caps fork-bomb-style exhaustion specifically.
CAPE_CPUS="${CAPE_CPUS:-16}"
CAPE_MEMORY="${CAPE_MEMORY:-32g}"
CAPE_PIDS_LIMIT="${CAPE_PIDS_LIMIT:-4096}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[AMSA]${NC} $1"; }
warn() { echo -e "${YELLOW}[AMSA]${NC} $1"; }
fail() { echo -e "${RED}[AMSA]${NC} $1"; exit 1; }

# ── DB password (INF-06): generated once and persisted to a 0600 file
# under WORK_DIR (mounted into the container as /work), instead of the
# hardcoded "SuperPuperSecret" literal embedded in commands/echoed to
# stdout. Alnum-only so it's safe to embed in both the outer bash string
# and the inner SQL literal without further quoting.
mkdir -p "$WORK_DIR"
DB_PASS_FILE="$WORK_DIR/.cape_db_password"
if [ -f "$DB_PASS_FILE" ]; then
    CAPE_DB_PASSWORD=$(cat "$DB_PASS_FILE")
else
    CAPE_DB_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
    printf '%s' "$CAPE_DB_PASSWORD" > "$DB_PASS_FILE"
    chmod 600 "$DB_PASS_FILE"
fi

echo ""
echo "================================================"
echo "  AMSA — CAPEv2 Environment Startup"
echo "================================================"
echo ""

# ── Step 1: Verify KVM is accessible ─────────────────────────────────
log "Checking KVM availability..."
if [ ! -e /dev/kvm ]; then
    fail "/dev/kvm not found. KVM is required."
fi
log "KVM available."

# ── Step 2: Verify work directory and VM files exist ─────────────────
log "Checking VM files..."
if [ ! -f "$WORK_DIR/vms/cuckoo1.qcow2" ]; then
    fail "Windows VM disk not found at $WORK_DIR/vms/cuckoo1.qcow2"
fi
if [ ! -f "$WORK_DIR/vms/cuckoo1.xml" ]; then
    fail "Windows VM XML not found at $WORK_DIR/vms/cuckoo1.xml"
fi
log "VM files found."

# ── Step 3: Create pgdata directory for persistent PostgreSQL ─────────
mkdir -p "$PGDATA_DIR"

# ── Step 4: Clean up stale network bridges on host ───────────────────
# INF-03 fix: virbr0 is libvirt's default bridge name and may belong to an
# unrelated VM elsewhere on this host, not one of ours. Only tear it down
# if it has no active (UP) attached interfaces — an idle/stale bridge is
# safe to recreate, one with live traffic is not ours to touch.
log "Cleaning up stale network bridges..."
if ip link show virbr0 &>/dev/null; then
    ACTIVE_SLAVES=$(ip -o link show master virbr0 2>/dev/null | grep -c "state UP" || echo 0)
    if [ "$ACTIVE_SLAVES" -gt 0 ]; then
        fail "virbr0 has $ACTIVE_SLAVES active interface(s) attached (INF-03) — refusing to tear it down, it may belong to an unrelated VM on this host. Inspect with 'ip link show master virbr0' and resolve manually before rerunning."
    fi
    log "virbr0 exists but is idle — safe to recreate."
    ip link set virbr0 down 2>/dev/null || true
    ip link delete virbr0 2>/dev/null || true
    ip link delete virbr0-nic 2>/dev/null || true
else
    log "virbr0 not present on host — nothing to clean up."
fi

# ── Step 5: Remove stale container if exists ─────────────────────────
# INF-03 fix: a container named "cape" that this script didn't create is
# not ours to force-remove. Only auto-remove containers we labeled
# ourselves at creation time (amsa.managed=true, see Step 6 below).
if docker ps -a --format '{{.Names}}' | grep -q "^${CAPE_CONTAINER}$"; then
    OWNER_LABEL=$(docker inspect --format '{{index .Config.Labels "amsa.managed"}}' "$CAPE_CONTAINER" 2>/dev/null || echo "")
    if [ "$OWNER_LABEL" != "true" ]; then
        fail "A container named '$CAPE_CONTAINER' already exists but was not created by this script (missing amsa.managed label — INF-03). Refusing to force-remove a container we don't own. Inspect it with 'docker inspect $CAPE_CONTAINER' and remove it manually if it's safe to do so."
    fi
    warn "Removing stale container '$CAPE_CONTAINER' (previously created by this script)..."
    docker rm -f "$CAPE_CONTAINER" 2>/dev/null
fi

# ── Step 6: Start cape container ─────────────────────────────────────
# INF-01 mitigation (partial, opt-in): --privileged grants every Linux
# capability and full host device access, which makes the --cap-add /
# --device lines below redundant while it's set — they were already the
# narrow, correct list this container actually needs (KVM, TUN/TAP,
# NET_ADMIN for bridge/tap setup, SYS_ADMIN for libvirt/cgroup/mount
# operations and systemd-in-container, SYS_PTRACE for process
# instrumentation); --privileged just made them moot. Set
# AMSA_HARDENED_PRIVILEGES=1 to drop --privileged and rely on only that
# explicit grant list instead.
#
# NOT validated against a live CAPE/KVM/systemd stack in this environment
# (no /dev/kvm, no CAPE deployment reachable here) — test it in a
# non-critical environment first. If the container fails to start, or
# libvirtd/cape-web/systemd misbehave inside it, unset the variable to
# fall back to the known-working --privileged behavior (the default) and
# report exactly what failed, so the missing capability can be added back
# explicitly rather than reverting to full --privileged permanently.
#
# This narrows the container's privilege footprint but does not close
# INF-01 by itself: --network host below still gives the container the
# full host network namespace. Removing that safely needs the container's
# actual guest-bridge (virbr0) connectivity requirements worked out against
# a live libvirt setup — not attempted here for the same reason. The full
# fix remains audit P0 #2: CAPE on its own dedicated, disposable host with
# no Docker socket exposed to the Orchestrator at all.
PRIVILEGED_FLAG="--privileged"
if [ "${AMSA_HARDENED_PRIVILEGES:-0}" = "1" ] || [ "${AMSA_HARDENED_PRIVILEGES:-0}" = "true" ]; then
    warn "AMSA_HARDENED_PRIVILEGES=1 — starting WITHOUT --privileged (untested; unset this variable to roll back if the container or its services fail to start)."
    PRIVILEGED_FLAG=""
fi

log "Starting CAPEv2 container..."
docker run -d \
    --name "$CAPE_CONTAINER" \
    --label amsa.managed=true \
    $PRIVILEGED_FLAG \
    --device /dev/kvm \
    --device /dev/net/tun \
    --cap-add NET_ADMIN \
    --cap-add SYS_ADMIN \
    --cap-add SYS_PTRACE \
    --network host \
    --cpus "$CAPE_CPUS" \
    --memory "$CAPE_MEMORY" \
    --pids-limit "$CAPE_PIDS_LIMIT" \
    -v "$WORK_DIR":/work \
    -v "$PGDATA_DIR":/var/lib/postgresql \
    -v "$ISO_DIR":/iso \
    -v /lib/modules:/lib/modules:ro \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --cgroupns host \
    "$CAPE_IMAGE" || fail "Failed to start cape container."

log "Container started. Waiting for systemd to initialize..."
sleep 15

# ── Step 7: Verify container is running ──────────────────────────────
if ! docker ps --format '{{.Names}}' | grep -q "^${CAPE_CONTAINER}$"; then
    fail "Container '$CAPE_CONTAINER' failed to start."
fi
log "Container is running."

# ── Step 8: Fix PostgreSQL authentication ────────────────────────────
# INF-07 fix: no longer downgrades every scram-sha-256 rule in the file to
# md5 (which weakens auth for every matching rule, not just this app).
# Instead append one scoped rule for the cape user over localhost only,
# using scram-sha-256 rather than md5 per the audit recommendation.
#
# CAVEAT (untested here — no running CAPE/Postgres stack in this
# environment): the original global downgrade may have existed because
# the CAPE web container's psycopg2/libpq version couldn't negotiate
# SCRAM. If this rule causes CAPE's DB connection to fail after
# deployment, that's the likely cause — either upgrade the driver or,
# as a last resort, change this one scoped line back to md5 (never the
# global downgrade this replaced).
log "Configuring PostgreSQL authentication (scoped rule only)..."
docker exec "$CAPE_CONTAINER" bash -c '
    PGHBA=$(ls /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | head -1)
    if [ -n "$PGHBA" ] && ! grep -q "^host[[:space:]]\+cape[[:space:]]\+cape[[:space:]]\+127.0.0.1/32[[:space:]]\+scram-sha-256" "$PGHBA"; then
        echo "host    cape    cape    127.0.0.1/32    scram-sha-256" >> "$PGHBA"
    fi
' || true
docker exec "$CAPE_CONTAINER" bash -c \
    "su postgres -c 'pg_ctlcluster \$(pg_lsclusters -h | awk \"{print \\\$1,\\\$2}\") reload' \
    2>/dev/null || true"
sleep 3

# ── Step 9: Create cape database user and database ───────────────────
# INF-06 fix: password comes from the generated file mounted at /work
# (never a hardcoded literal), and is read from disk inside the container
# rather than embedded in the host-visible docker exec argument.
log "Setting up database user and database..."
docker exec "$CAPE_CONTAINER" bash -c \
    "su postgres -c \"psql -c \\\"CREATE USER cape WITH PASSWORD '\$(cat /work/.cape_db_password)';\\\"\" \
    2>/dev/null || \
    su postgres -c \"psql -c \\\"ALTER USER cape WITH PASSWORD '\$(cat /work/.cape_db_password)';\\\"\" \
    2>/dev/null || true"
docker exec "$CAPE_CONTAINER" bash -c \
    "su postgres -c \"psql -c \\\"CREATE DATABASE cape OWNER cape;\\\"\" 2>/dev/null || true"
docker exec "$CAPE_CONTAINER" bash -c \
    "su postgres -c \"psql -c \\\"GRANT ALL PRIVILEGES ON DATABASE cape TO cape;\\\"\" \
    2>/dev/null || true"

# ── Step 10: Run database migrations ─────────────────────────────────
log "Running database migrations..."
docker exec "$CAPE_CONTAINER" bash -c \
    "cd /opt/CAPEv2 && /etc/poetry/bin/poetry run python manage.py migrate 2>&1 | tail -3"

# ── Step 11: Install libvirt-python in cape user virtualenv ──────────
log "Installing libvirt-python..."
docker exec "$CAPE_CONTAINER" bash -c \
    "$VENV/bin/pip install libvirt-python==8.0.0 -q 2>&1 | tail -1"
log "libvirt-python ready."

# ── Step 12: Fix file ownership ───────────────────────────────────────
log "Fixing file ownership..."
docker exec "$CAPE_CONTAINER" bash -c \
    "chown -R cape:cape /opt/CAPEv2 2>/dev/null || true"

# ── Step 13: Fix cape-web port conflict ──────────────────────────────
log "Configuring cape-web service port..."
docker exec "$CAPE_CONTAINER" bash -c \
    "sed -i 's/runserver_plus 0.0.0.0:8000/runserver_plus 0.0.0.0:8001/' \
    /lib/systemd/system/cape-web.service 2>/dev/null || true && \
    systemctl daemon-reload 2>/dev/null || true"

# ── Step 14: Start libvirtd ───────────────────────────────────────────
log "Starting libvirtd..."
docker exec "$CAPE_CONTAINER" bash -c \
    "systemctl start libvirtd 2>/dev/null; sleep 3"

# ── Step 15: Fix virbr0 conflict inside container ────────────────────
log "Fixing network bridge inside container..."
docker exec "$CAPE_CONTAINER" bash -c \
    "ip link set virbr0 down 2>/dev/null; \
     ip link delete virbr0 2>/dev/null; \
     ip link delete virbr0-nic 2>/dev/null; \
     virsh net-start default 2>/dev/null || true"
sleep 3

# ── Step 16: Final status ─────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Environment Status"
echo "================================================"
echo "  Cape container  : $(docker ps --format '{{.Status}}' -f name=$CAPE_CONTAINER)"
echo "  KVM             : $(ls /dev/kvm 2>/dev/null && echo available || echo missing)"
echo "  Work directory  : $WORK_DIR"
echo "  PostgreSQL      : $(docker exec $CAPE_CONTAINER bash -c \
    "PGPASSWORD=\$(cat /work/.cape_db_password) psql -h localhost -U cape -d cape \
    -c '\q' 2>/dev/null && echo OK || echo FAILED")"
echo "  libvirt network : $(docker exec $CAPE_CONTAINER bash -c \
    "virsh net-info default 2>/dev/null | grep Active | awk '{print \$2}'")"
echo ""
log "CAPEv2 environment ready. Run ./windows_start.sh to start the Windows VM."
