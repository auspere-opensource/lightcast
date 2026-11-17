#!/usr/bin/env bash
# Run a command on macOS under a memory, process-count and wall-clock ceiling.
#
# macOS has no cgroups and does not enforce RLIMIT_AS, so this is a watchdog: it samples the
# command's whole process tree every second and kills the tree when the summed resident memory,
# the process count, or the elapsed time crosses its limit.
#
# Usage: tools/run-bounded-macos.sh MEMORY_MB MAX_PROCS TIMEOUT_SECONDS -- COMMAND [ARG...]
set -uo pipefail

if [[ $# -lt 5 || "$4" != "--" ]]; then
  echo "usage: $0 MEMORY_MB MAX_PROCS TIMEOUT_SECONDS -- COMMAND [ARG...]" >&2
  exit 2
fi
mem_mb="$1"; max_procs="$2"; timeout_s="$3"; shift 4

"$@" &
root=$!

tree() { # print root and all descendants
  local p kids
  echo "$1"
  kids=$(pgrep -P "$1" 2>/dev/null || true)
  for p in $kids; do tree "$p"; done
}

kill_tree() {
  local pids
  pids=$(tree "$root" | tr '\n' ' ')
  kill -TERM $pids 2>/dev/null || true
  sleep 2
  kill -KILL $pids 2>/dev/null || true
}

start=$(date +%s)
peak=0
while kill -0 "$root" 2>/dev/null; do
  pids=$(tree "$root" | paste -sd, -)
  n=$(echo "$pids" | tr ',' '\n' | grep -c .)
  rss_kb=$(ps -o rss= -p "$pids" 2>/dev/null | awk '{s+=$1} END {print s+0}')
  rss_mb=$((rss_kb / 1024))
  (( rss_mb > peak )) && peak=$rss_mb
  now=$(date +%s)
  if (( rss_mb > mem_mb )); then
    echo "run-bounded-macos: memory ${rss_mb} MB exceeded ${mem_mb} MB; killing" >&2; kill_tree; wait "$root"; exit 137
  fi
  if (( n > max_procs )); then
    echo "run-bounded-macos: ${n} processes exceeded ${max_procs}; killing" >&2; kill_tree; wait "$root"; exit 137
  fi
  if (( now - start > timeout_s )); then
    echo "run-bounded-macos: ${timeout_s}s timeout; killing" >&2; kill_tree; wait "$root"; exit 124
  fi
  sleep 1
done
wait "$root"
rc=$?
echo "run-bounded-macos: exit ${rc}, peak ${peak} MB, $(( $(date +%s) - start ))s" >&2
exit $rc
