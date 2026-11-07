#!/system/bin/sh
# dumpset.sh <part> [part...]
# dd each named partition to /sdcard/Download/dump/ as root, recording
# size / elapsed time / sha256 per partition.
D=/sdcard/Download/dump
mkdir -p $D
L=$D/dump.log
for n in "$@"; do
  src=/dev/block/by-name/$n
  if [ ! -e "$src" ]; then
    echo "[SKIP] $n  not present in by-name" >> $L
    continue
  fi
  exp=$(blockdev --getsize64 "$src" 2>/dev/null)
  t0=$(date +%s)
  dd if="$src" of="$D/$n.img" bs=1048576 2>>$L
  rc=$?
  t1=$(date +%s)
  got=$(stat -c %s "$D/$n.img" 2>/dev/null)
  h=$(sha256sum "$D/$n.img" 2>/dev/null | cut -c1-32)
  flag=OK
  [ "$exp" = "$got" ] || flag=SIZE_MISMATCH
  echo "[$flag] $n exp=$exp got=$got rc=$rc t=$((t1-t0))s sha256=$h" >> $L
done
sync
echo "[DONE] $(date)" >> $L
