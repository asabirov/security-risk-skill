#!/usr/bin/env bash
# sandbox-run.sh: run one shell command line inside an OS-enforced, network-less container.
# Usage: sandbox-run.sh '<shell command line>'   (stdin is passed through; SANDBOX_TIMEOUT=seconds, default 300, max 1800)
# Container view: /work/target = audited source (read-only), /work/scratch = this session's scratch (read-write, also the cwd),
# SANDBOX_SCRATCH=<existing directory inside this session folder> mounts that directory as /work/scratch instead.
# installed dependencies read-only at /work/node_modules (Node) or /work/pydeps (Python, on PYTHONPATH), /tmp = 512 MB tmpfs.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd -L)"
# shellcheck source=/dev/null
. "$here/sandbox.conf"
[ $# -ge 1 ] || { echo "usage: $0 '<shell command line>'" >&2; exit 64; }
cmd="$*"
if [ -n "${SANDBOX_SCRATCH:-}" ]; then
  s="$(realpath -e -- "$SANDBOX_SCRATCH" 2>/dev/null)" || { echo "sandbox-run.sh: SANDBOX_SCRATCH does not exist" >&2; exit 64; }
  case "$s/" in "$(realpath -e "$here")"/*/) SCRATCH_DIR="$s"; chmod 777 "$s" 2>/dev/null ;; *) echo "sandbox-run.sh: SANDBOX_SCRATCH must be inside $here" >&2; exit 64 ;; esac
fi
timeout_s="${SANDBOX_TIMEOUT:-300}"
[ "$timeout_s" -gt 1800 ] 2>/dev/null && timeout_s=1800
name="srbench-${SESSION}-$(date +%s%N)"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
start=$(date +%s)
printf '%s start %s timeout=%ss cmd=%q\n' "$(date -u +%FT%TZ)" "$name" "$timeout_s" "$cmd" >> "$LOG"
echo "  scratch=$SCRATCH_DIR" >> "$LOG"
timeout --kill-after=2 "$timeout_s" docker run --rm -i --name "$name" --label srbench=1 \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 2g --cpus 2 --user 1000:1000 --tmpfs /tmp:size=512m --ulimit fsize=536870912 \
  -v "$TARGET_DIR:/work/target:ro" -v "$DEPS_DIR:$DEPS_MOUNT:ro" -v "$SCRATCH_DIR:/work/scratch:rw" \
  -e HOME=/tmp "${EXTRA_ENV[@]}" -w /work/scratch "$IMAGE" sh -c "umask 000; $cmd"
rc=$?
[ $(( $(date +%s) - start )) -ge "$timeout_s" ] && echo "sandbox-run.sh: command stopped after ${timeout_s}s timeout" >&2
printf '%s end %s rc=%s\n' "$(date -u +%FT%TZ)" "$name" "$rc" >> "$LOG"
exit "$rc"
