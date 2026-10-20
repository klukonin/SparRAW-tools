#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# navtest.sh — гипотеза: 0x886d20 = предел NAV (мкс), 0x886d24 = включение NAV,
# 0x886e84 = текущий NAV. Под iperf 150 быстрых чтений 0x886e84 на обоих узлах
# при: штатно; d20=100; d20=5000,d24=0. Перед опытом — питание обоих узлов.
cd "$SPARRAW"
OUT=SparRAW-firmware/6.2/build/bench-62-mix/navtest.log
D=/sys/kernel/debug/ieee80211/phy0/wil6210
S='D='$D'; i=0; while [ $i -lt 150 ]; do echo 0x886e84 > $D/mem_addr; v=$(cat $D/mem_val); echo -n "${v##*= } "; i=$((i+1)); done; echo'
samp() {
  ssh root@$NODE_STA 'iperf3 -c 192.168.60.1 -t 20 >/dev/null 2>&1' & sleep 4
  for n in 11 12; do echo "$1 .$n $(ssh root@$(node $n) "$S")" >> $OUT; done
  wait
}
w() { for n in 11 12; do ssh root@$(node $n) "echo '$1 $2' > $D/mem_write; echo $1 > $D/mem_addr; cat $D/mem_val"; done | tr '\n' ' ' >> $OUT; echo >> $OUT; }
echo "## navtest $(date +%T)" > $OUT
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || { echo "# станция не подключилась" >> $OUT; exit 1; }
ssh root@$NODE_AP 'iperf3 -s -D >/dev/null 2>&1'; sleep 25
samp base
w 0x886d20 0x64;  samp d20_100
w 0x886d20 0x1388; w 0x886d24 0x0; samp d24_0
w 0x886d24 0x1; samp restored
echo "# готово $(date +%T)" >> $OUT
