#!/bin/sh
# Harmless canary — exercises the behaviours the backend must observe, with
# no payload, no persistence beyond the disposable VM, no real network reach.
echo "sandboxgen canary starting pid=$$"
# 1. spawn a child process (behaviour: >1 process)
( sleep 2; echo child ) &
# 2. write a file outside the task dir (behaviour: writes_outside_workdir)
echo "canary was here $(date)" > /root/canary_marker.txt
# 3. attempt outbound network (blocked by restrict=on, recorded as attempted).
#    bash's /dev/tcp needs no client tool (the minimal guest has no nc/curl).
timeout 5 bash -c 'exec 3<>/dev/tcp/93.184.216.34/80' 2>/dev/null || true
# 4. a DNS lookup attempt via the libc resolver (no nslookup/dig in the guest)
timeout 5 getent hosts sandboxgen-canary.example >/dev/null 2>&1 || true
wait
echo "sandboxgen canary done"
