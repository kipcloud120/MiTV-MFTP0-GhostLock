#!/system/bin/sh
# Extra captures: eMMC boot partitions + primary/backup partition table area.
D=/sdcard/Download/dump
L=$D/dump.log
for n in mmcblk0boot0 mmcblk0boot1; do
  dd if=/dev/block/$n of=$D/$n.img bs=1048576 2>>$L
  echo "[RAW] $n got=$(stat -c %s $D/$n.img) sha256=$(sha256sum $D/$n.img | cut -c1-32)" >> $L
done
SZ=$(blockdev --getsz /dev/block/mmcblk0)
echo "[RAW] mmcblk0 sectors=$SZ" >> $L
dd if=/dev/block/mmcblk0 of=$D/gpt_primary.img bs=512 count=2048 2>>$L
dd if=/dev/block/mmcblk0 of=$D/gpt_backup.img bs=512 skip=$((SZ-2048)) count=2048 2>>$L
for n in gpt_primary gpt_backup; do
  echo "[RAW] $n got=$(stat -c %s $D/$n.img) sha256=$(sha256sum $D/$n.img | cut -c1-32)" >> $L
done
echo "[RAWDONE] $(date)" >> $L
