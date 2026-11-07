#!/usr/bin/env bash
# klogd_ctl.sh - start / stop / inspect the kernel crash black box.
#
#   ./klogd_ctl.sh start
#   ./klogd_ctl.sh status
#   ./klogd_ctl.sh tail 80
#   ./klogd_ctl.sh stop
#
# The daemon itself is ghost/klogd.sh. It is pushed to /sdcard first, then copied to
# /data/anr (ext4) and started from there: /sdcard is FUSE, and a FUSE file is a poor
# home for something that has to survive a kernel lockup.
#
# stop matches the full command line of the daemon only. Do not use pkill -f with a
# short pattern here: the root agent runs our commands through a script whose *content*
# contains the pattern, and pkill -f has already killed the agent once that way.
set -u

ADB="${ADB:-/d/AI/DeepSeek-Harness/K90Ultra/_fbtools/adb.exe}"
DEV="${DEV:-192.168.31.243:5555}"
HERE="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"

r() { bash "$HERE/r.sh" -s "$DEV" "$@"; }

push() {
  MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 "$ADB" -s "$DEV" push "$HERE/klogd.sh" //sdcard/Download/klogd.sh >/dev/null 2>&1 \
    || { echo "klogd_ctl: push failed (adb connected? DEV=$DEV)" >&2; exit 1; }
}

cmd="${1:-status}"
case "$cmd" in
  start)
    push
    r 'cp /sdcard/Download/klogd.sh /data/anr/klogd.sh; chmod 0755 /data/anr/klogd.sh
       if ps -A -o ARGS | grep -q "[/]data/anr/klogd.sh"; then
         echo "klogd already running"
       else
         ( /system/bin/sh /data/anr/klogd.sh </dev/null >/dev/null 2>&1 & )
         sleep 1
         echo "klogd started"
       fi
       ps -A -o PID,ARGS | grep "[/]data/anr/klogd.sh"'
    ;;
  stop)
    r 'for p in $(ps -A -o PID,ARGS | grep "[/]data/anr/klogd.sh" | sed -E "s/^ *([0-9]+).*/\1/"); do
         kill "$p" && echo "killed $p"
       done
       ps -A -o ARGS | grep -q "[/]data/anr/klogd.sh" && echo "still running" || echo "stopped"'
    ;;
  status)
    r 'ps -A -o PID,ARGS | grep "[/]data/anr/klogd.sh" || echo "not running"
       ls -l /data/anr/kernel.log* 2>/dev/null || echo "no log yet"
       echo "--- last lines ---"
       tail -n 5 /data/anr/kernel.log 2>/dev/null'
    ;;
  tail)
    n="${2:-40}"
    r "tail -n $n /data/anr/kernel.log"
    ;;
  *)
    echo "usage: klogd_ctl.sh start|stop|status|tail [n]" >&2
    exit 2
    ;;
esac
