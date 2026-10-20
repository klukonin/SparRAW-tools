#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# rsswin.sh — окно ожидания конца развёртки [0x8020c4] (host 0x9420c4) на обоих
# узлах: фазы по 20 с «база / ×2 / база / ×2» в одной загрузке; в фазе ×2
# значение переписывается раз в секунду (ucode_cmd_0x18 его перетирает).
# Считаем у AP состояния BF из uc_trace по относительному времени хвоста.
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix
S=${TMPDIR:-/tmp}/rsswin; mkdir -p "$S"
W=20
if [ "$1" = reboot ]; then
  timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
  timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
  timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done'
  sleep 60
fi
wr() { for h in 11 12; do ssh root@$(node $h) "D=/sys/kernel/debug/ieee80211/phy0/wil6210; echo '0x9420c4 $1' > \$D/mem_write"; done; }
cnt() { for h in 11 12; do timeout 15 ssh root@$(node $h) 'cat /sys/kernel/debug/ieee80211/phy0/wil6210/uc_trace' > $S/rw_$h.bin
  python3 SparRAW-tools/host/wil_uc_collect.py $S/rw_$h.bin -s SparRAW-firmware/6.2/ref/strings-uc.bin --raw 2>/dev/null | awk 'NR>1' > $S/rw_$h.txt
  T=$(tail -1 $S/rw_$h.txt | awk '{print $1}'); P=$(cat $S/rw_$h.T 2>/dev/null); echo "$T" > $S/rw_$h.T
  [ "$T" = "$P" ] && echo ".$h СБОРЩИК СТОИТ (хвост $T) — фаза недействительна"
  echo ".$h $(awk -v T=$T -v W=$W '$1>=T-W' $S/rw_$h.txt | grep -oE 'state:[0-9]+:[0-9]+' | sort | uniq -c | sort -rn | awk '{printf "%s=%s ",$2,$1}')"; done
  echo "ping: $(ssh root@$NODE_STA 'ping -q -c 5 -W 1 192.168.60.1 | grep loss')"; }
for ph in base x2 base x2; do
  if [ $ph = x2 ]; then v=0x00052a50; else v=0x00029528; fi
  wr $v; i=0; while [ $i -lt $W ]; do [ $ph = x2 ] && wr $v; sleep 1; i=$((i+1)); done
  echo "### $ph ($v) $(date +%T)"; cnt
done
wr 0x00029528
