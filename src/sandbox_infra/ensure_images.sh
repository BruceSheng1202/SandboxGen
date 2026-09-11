#!/usr/bin/env bash
# Restore container images from their persistent NFS tarballs if the local
# podman store (on scratch, which reclaims on a TTL) has lost them. Cheap when
# images are present; a few seconds to load when they are not.
set -euo pipefail
STORE="${SANDBOXGEN_IMAGE_STORE:-/home/$USER/sandboxgen/vmstore/images}"
declare -A IMG=(
  [localhost/sandboxgen-qemu:alpine3.20]="$STORE/sandboxgen-qemu.tar"
  [localhost/sandboxgen-harness:py312]="$STORE/sandboxgen-harness.tar"
  [localhost/sandboxgen-analyze:py312]="$STORE/sandboxgen-analyze.tar"
)
for name in "${!IMG[@]}"; do
  if ! podman image exists "$name" 2>/dev/null; then
    tar="${IMG[$name]}"
    if [[ -f "$tar" ]]; then echo "restoring $name from $tar"; podman load -i "$tar" >/dev/null
    else echo "WARN: $name missing and no tarball at $tar" >&2; fi
  fi
done
