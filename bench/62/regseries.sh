#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# regseries.sh — серия опытов с возмущением для неясных регистров (REGS-KNOWN).
# Каждый опыт: конфиг через uci -> питание обоих узлов -> линк -> снимки
# (5 в простое, 5 под iperf) + быстрая серия TSF/ec0/fc4. В конце — исходный конфиг.
cd "$SPARRAW"
OUT=SparRAW-firmware/6.2/build/bench-62-mix/regseries.log
REGS="0x886eb8 0x886d64 0x886fc4 0x886ec0 0x886d18 0x886d1c 0x886d58 0x880074 0x880078 0x88007c 0x880200 0x880204 0x8830ec 0x88317c 0x8836c8 0x8837b0 0x8837d8 0x8837dc 0x8837f4 0x883800 0x883980 0x8839bc 0x883aa4 0x883b78 0x88405c 0x884060 0x886028 0x886d14 0x886d20 0x886d24 0x886d28 0x886d40 0x886d44 0x886d5c 0x886d60 0x886dac 0x886de8 0x886dec 0x886e84 0x886f60 0x886f78 0x886f7c 0x886fc0 0x8890f8"
SNAP='D=/sys/kernel/debug/ieee80211/phy0/wil6210; for a in '"$REGS"'; do echo $a > $D/mem_addr; v=$(cat $D/mem_val); echo -n "${v##*= } "; done; echo'
SER='D=/sys/kernel/debug/ieee80211/phy0/wil6210; r(){ echo $1 > $D/mem_addr; v=$(cat $D/mem_val); echo -n "${v##*= } "; }; i=0; while [ $i -lt 20 ]; do r 0x886eb8; r 0x886ec0; r 0x886eb8; r 0x886fc4; echo; i=$((i+1)); done'
ap()  { ssh -o ConnectTimeout=6 root@$NODE_AP "$1"; }
sta() { ssh -o ConnectTimeout=6 root@$NODE_STA "$1"; }
cfg() { # BI канал частота sta_disabled
  ap  "uci set wireless.radio0.beacon_int=$1; uci set wireless.radio0.channel=$2; uci commit wireless; sync"
  sta "uci set wireless.radio0.channel=$2; uci -q delete wireless.radio0.scan_list; uci add_list wireless.radio0.scan_list=$3; uci set wireless.default_radio0.disabled=$4; uci commit wireless; sync"
}
snap() { for i in 1 2 3 4 5; do for n in 11 12; do echo "$E $1 .$n $(ssh -o ConnectTimeout=6 root@$(node $n) "$SNAP")" >> $OUT; done; sleep 1; done; }
run() { # имя BI канал частота sta_disabled
  E=$1; echo "## $E $(date +%T) BI=$2 ch=$3 sta_disabled=$5" >> $OUT
  cfg $2 $3 $4 $5
  timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
  timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
  if [ "$5" = 0 ]; then
    timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || { echo "# $E: станция не подключилась" >> $OUT; return; }
  else
    timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_AP "iw dev phy0-ap0 info 2>/dev/null | grep -q channel" 2>/dev/null; do sleep 5; done'
    timeout 120 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA true 2>/dev/null; do sleep 5; done'
  fi
  sleep 30
  echo "# $E ap: $(ap 'iw dev phy0-ap0 info | grep -E "channel"' | tr -s ' \t' ' ') sta: $(sta 'iw dev phy0-sta0 link | grep -E "freq|beacon" ' | tr -s ' \t\n' ' ')" >> $OUT
  snap idle
  if [ "$5" = 0 ]; then
    ap 'iperf3 -s -D >/dev/null 2>&1'; sleep 1
    sta 'iperf3 -c 192.168.60.1 -t 25 >/dev/null 2>&1' & sleep 5
    snap iperf; wait
  fi
  for n in 11 12; do ssh root@$(node $n) "$SER" | sed "s/^/$E fast .$n /" >> $OUT; done
}
: > $OUT; echo "# регистры: $REGS" >> $OUT
run base   100 1 58320 0
run bi200  200 1 58320 0
run bi50    50 1 58320 0
run ch2    100 2 60480 0
run aponly 100 1 58320 1
cfg 100 1 58320 0
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
echo "# готово $(date +%T), конфиг возвращён (BI 100, канал 1, станция включена)" >> $OUT
