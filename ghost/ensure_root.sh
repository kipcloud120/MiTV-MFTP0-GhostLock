#!/bin/bash
# ensure_root.sh - idempotent "root agent + PFN watcher" keepalive.
#
# Difference from a plain setup script: the TvService property trigger is only
# fired when the agent is *not* already running, so repeated invocations do not
# detach a new agent every time. The PFN watcher always uses the long-lived
# pfnd2.sh variant.
#
# Usage:  DEV=<tv-ip>:5555 bash ghost/ensure_root.sh
#
# Env:
#   DEV  adb serial / host:port of the target (required)
#   ADB  path to the adb binary (default: adb on PATH)
set -u
: "${DEV:?set DEV=<tv-ip>:5555}"
ADB="${ADB:-adb}"
HERE="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

SH() { "$ADB" -s "$DEV" shell "$@" 2>&1 | tr -d '\r'; }

"$ADB" connect "$DEV" >/dev/null 2>&1

# 1) root agent
if SH 'ps -A -o ARGS | grep -q "[a]gent.sh" && echo yes' | grep -q yes; then
  echo "[ensure] agent already running"
else
  echo "[ensure] agent missing, starting one"
  # Write the arguments property first, then the code property. The latter is a
  # property trigger in init, so init runs the payload as uid 0.
  SH 'service call TvService 4400 s16 x s16 sh,/sdcard/Download/agent.sh' >/dev/null
  sleep 1
  SH 'service call TvService 4400 s16 s s16 sh,/sdcard/Download/agent.sh' >/dev/null
  sleep 3
fi

# 2) PFN watcher (long-lived variant)
if SH 'ps -A -o ARGS | grep -q "[p]fnd2.sh" && echo yes' | grep -q yes; then
  echo "[ensure] pfnd2 already running"
else
  echo "[ensure] pfnd2 missing, starting one"
  MSYS2_ARG_CONV_EXCL='*' "$ADB" -s "$DEV" push "$HERE/pfnd2.sh" //sdcard/Download/pfnd2.sh >/dev/null 2>&1
  printf 'pkill -f pfnd.sh 2>/dev/null\n( /system/bin/sh /sdcard/Download/pfnd2.sh </dev/null >/dev/null 2>&1 & )\n' > "$HERE/cmd_boot_pfnd2.sh"
  MSYS2_ARG_CONV_EXCL='*' "$ADB" -s "$DEV" push "$HERE/cmd_boot_pfnd2.sh" //sdcard/Download/cmd.sh >/dev/null 2>&1
  sleep 3
fi

SH 'printf "agent=%s pfnd2=%s\n" "$(ps -A -o ARGS | grep -c "[a]gent.sh")" "$(ps -A -o ARGS | grep -c "[p]fnd2.sh")"'
