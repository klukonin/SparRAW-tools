#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# soak.sh — раз в минуту: ping по 60 ГГц в обе стороны + ключевые слова обоих узлов
O=$(dirname $0); L=$O/soak.log
while :; do
  T=$(date +%F_%T)
  P1=$(timeout 20 ssh -o ConnectTimeout=5 root@$NODE_AP 'ping -c 5 -W 1 192.168.60.2 | tail -2 | tr "\n" " "' 2>&1)
  P2=$(timeout 20 ssh -o ConnectTimeout=5 root@$NODE_STA 'ping -c 5 -W 1 192.168.60.1 | tail -2 | tr "\n" " "' 2>&1)
  K=""
  for h in 11 12; do
    K="$K .$h:$(timeout 20 ssh -o ConnectTimeout=5 root@$(node $h) 'D=$(ls -d /sys/kernel/debug/ieee80211/phy*/wil6210|head -1); for a in 0x941034 0x940ef4 0x941b2c 0x886da4 0x9410a4; do echo $a > $D/mem_addr; cat $D/mem_val | sed "s/.*= //"; done | tr "\n" " "; uptime | sed "s/.*up //;s/,.*//"; dmesg | grep -c "FW restarted"' 2>&1 | tr "\n" " ")"
  done
  echo "$T | 11->12: $P1 | 12->11: $P2 |$K" >> $L
  sleep 60
done
