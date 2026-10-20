#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# bfmeasure.sh ТЕГ [СЕК] — окно СЕК (30) по часам узлов: пинг в обе стороны,
# затем снимок кольца ucode (патч 910: 1 МБ, чтение НЕ освобождает) и подсчёт
# исходов BF только по пачкам внутри окна (--since/--until = /proc/uptime узла).
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix; T=$1; W=${2:-30}
t11=$(timeout 8 ssh root@$NODE_AP 'cut -d" " -f1 /proc/uptime'); t12=$(timeout 8 ssh root@$NODE_STA 'cut -d" " -f1 /proc/uptime')
timeout $((W+10)) ssh root@$NODE_STA "ping -q -c $((W/2)) -W 1 192.168.60.1 | tail -2" > /tmp/bfm_up.txt 2>&1 &
timeout $((W+10)) ssh root@$NODE_AP "sleep $((W/2)); ping -q -c $((W/2-1)) -W 1 192.168.60.2 | tail -2" > /tmp/bfm_dn.txt 2>&1 &
wait
for h in 11 12; do
  eval s=\$t$h
  timeout 15 ssh root@$(node $h) 'cut -d" " -f1 /proc/uptime; cat /sys/kernel/debug/ieee80211/phy0/wil6210/uc_trace' > $B/bfm_${T}_$h.raw
  e=$(head -1 $B/bfm_${T}_$h.raw); tail -c +$(( $(head -1 $B/bfm_${T}_$h.raw | wc -c) + 1 )) $B/bfm_${T}_$h.raw > $B/bfm_${T}_$h.bin
  echo "== .$h $T  окно $s..$e"
  python3 SparRAW-tools/host/wil_uc_collect.py $B/bfm_${T}_$h.bin -s SparRAW-firmware/6.2/ref/strings-uc.bin --raw --since $s --until $e 2>/dev/null | head -1
  python3 SparRAW-tools/host/wil_uc_collect.py $B/bfm_${T}_$h.bin -s SparRAW-firmware/6.2/ref/strings-uc.bin --raw --since $s --until $e | grep -oE "bf_sm_handler in state:[0-9]+:[0-9]+|triggers:[0-9]+|failure [0-9]|disable RS" | sort | uniq -c | sort -rn | head -10
done
echo "uplink:   $(tr '\n' ' ' < /tmp/bfm_up.txt)"; echo "downlink: $(tr '\n' ' ' < /tmp/bfm_dn.txt)"
