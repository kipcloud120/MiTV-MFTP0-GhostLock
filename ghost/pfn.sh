#!/system/bin/sh
{
REQ=$(cat /sdcard/Download/g9_req.txt 2>/dev/null)
PID=${REQ% *}
VA=${REQ#* }
SKIPHEX=$(printf "%s" "$VA" | sed "s/...$//")
SKIP=$((0x$SKIPHEX))
echo "=== $(date) req=$REQ skip=$SKIP" >> /sdcard/Download/pfn.log
if [ ! -d "/proc/$PID" ]; then
  echo "PROC GONE pid=$PID" >> /sdcard/Download/pfn.log
  exit 0
fi
if [ ! -r "/proc/$PID/pagemap" ]; then
  echo "PAGEMAP UNREADABLE pid=$PID" >> /sdcard/Download/pfn.log
  ls -la "/proc/$PID/pagemap" >> /sdcard/Download/pfn.log 2>&1
  exit 0
fi
ENT=$(dd if="/proc/$PID/pagemap" bs=8 skip=$SKIP count=1 2>/sdcard/Download/dd.err | od -A n -t x8 | tr -d " \n")
DDE=$(cat /sdcard/Download/dd.err 2>/dev/null)
PFN_HEX=$(printf "%s" "$ENT" | cut -c3-16)
echo "ent=$ENT dderr=$DDE pfn=$PFN_HEX" >> /sdcard/Download/pfn.log
if [ -n "$PFN_HEX" ] && [ "$PFN_HEX" != "00000000000000" ]; then
  printf "%s\n" "$PFN_HEX" > /sdcard/Download/g9_pfn.txt
else
  echo "BAD ENTRY" >> /sdcard/Download/pfn.log
fi
} 2>&1
