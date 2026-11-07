#!/system/bin/sh
# klogd.sh - kernel crash black box for MiTV-MFTP0.
#
# Why this exists: `pstore total 0` on this device, so a kernel that hangs or oopses
# leaves nothing behind. When --walk locked the kernel up, the only evidence was that
# the watchdog rebooted us about 2.5 minutes later; the trace itself was gone. This
# keeps a copy of dmesg on /data (ext4), which survives a hard reset.
#
# Three things this device forced on the design, all measured:
#
#  1. No `dmesg -w`. toybox 0.7.6-android block-buffers follow mode's stdout: the first
#     dump flushed in 4 KB blocks and looked fine, but later lines sat in that buffer and
#     never reached the pipe. A marker written to /dev/kmsg showed up in dmesg and never
#     in the log. So: poll a fresh dmesg instead.
#
#  2. No big shell variables. `printf` is toybox here, not a builtin, so passing a full
#     dmesg (~580 KB) as an argument dies with "Argument list too long". Everything goes
#     through files and pipes.
#
#  3. No writing every second, and no scratch copy. Steady-state cost is one
#     `dmesg | tail -n 1`. This TV prints audio parameters about once a second, so a
#     temp copy of the whole buffer would be rewritten continuously; only the delta is
#     ever appended, and only when there is one.
#
# Anchor: the last line already written. Each time it changes, everything after its last
# occurrence is appended. If it is no longer present (ring buffer moved further than the
# previous snapshot), the tail is appended with a seam marker rather than silently lost.
#
# Start detached (see klogd_ctl.sh):
#   ( /system/bin/sh /data/anr/klogd.sh </dev/null >/dev/null 2>&1 & )
#
# Never uses dmesg -c / -C: clearing the ring buffer would rob every other consumer on
# the device, including whatever we are trying to observe.

LOG=/data/anr/kernel.log
MAX_BYTES=8388608
POLL=1
HEARTBEAT=300

mkdir -p /data/anr 2>/dev/null

if [ -f "$LOG" ]; then
  size=$(wc -c < "$LOG" 2>/dev/null || echo 0)
  [ "$size" -gt "$MAX_BYTES" ] && mv -f "$LOG" "$LOG.1"
fi

{
  echo "=== klogd start $(date) pid=$$ boot=$(cat /proc/sys/kernel/random/boot_id) uptime=$(cut -d. -f1 /proc/uptime)s"
} >> "$LOG"

anchor=""
first=1
ticks=0

while true; do
  last=$(dmesg 2>/dev/null | tail -n 1)

  if [ -n "$last" ] && [ "$last" != "$anchor" ]; then
    if [ "$first" = 1 ]; then
      dmesg 2>/dev/null >> "$LOG"
      first=0
    else
      # Last match: the kernel can print the identical line more than once.
      # Two reads, no snapshot file: this TV chatters (audio params once a second), so a
      # temp copy of the whole buffer would be rewritten constantly and wear the eMMC.
      # Only the delta is ever written, and only when there is one.
      ln=$(dmesg 2>/dev/null | grep -n -F -x -- "$anchor" | tail -n 1 | cut -d: -f1)
      if [ -n "$ln" ]; then
        dmesg 2>/dev/null | tail -n +$((ln + 1)) >> "$LOG"
      else
        {
          echo "=== klogd: anchor lost at uptime=$(cut -d. -f1 /proc/uptime)s, tail 400 follows ==="
          dmesg 2>/dev/null | tail -n 400
        } >> "$LOG"
      fi
    fi
    sync
    anchor="$last"
  fi

  ticks=$((ticks + 1))
  if [ $((ticks % HEARTBEAT)) -eq 0 ]; then
    echo "=== klogd alive $(date) uptime=$(cut -d. -f1 /proc/uptime)s lines=$(wc -l < "$LOG" 2>/dev/null)" >> "$LOG"
  fi

  sleep $POLL
done
