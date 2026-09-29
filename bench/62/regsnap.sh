#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# regsnap.sh ТЕГ — снимки неясных регистров (ref/REGS-KNOWN «смысл не установлен»)
# на обоих узлах в трёх состояниях: линк в простое, под iperf, станция отключена.
# Перед опытом оба узла передёргиваются питанием (правило стенда).
cd "$SPARRAW"
T=${1:-regsnap}; OUT=SparRAW-firmware/6.2/build/bench-62-mix/regsnap_$T.log
REGS="0x886eb8 0x886ebc 0x886d64 0x886fc4 0x886fc8 0x8830ec 0x88317c 0x8836c8 0x8837b0 0x8837d8 0x8837dc 0x8837f4 0x883800 0x883980 0x883984 0x883988 0x88398c 0x883990 0x883994 0x883998 0x88399c 0x8839bc 0x8839c0 0x8839c4 0x8839c8 0x8839cc 0x8839d0 0x8839d4 0x8839d8 0x883aa4 0x883b78 0x88405c 0x884060 0x886028 0x886d14 0x886d20 0x886d24 0x886d28 0x886d40 0x886d44 0x886d5c 0x886d60 0x886dac 0x886de8 0x886dec 0x886e84 0x886ec0 0x886f60 0x886f78 0x886f7c 0x886fc0 0x8890f8"
SNAP='D=/sys/kernel/debug/ieee80211/phy0/wil6210; for a in '"$REGS"'; do echo $a > $D/mem_addr; v=$(cat $D/mem_val); echo -n "${v##*= } "; done; echo'
snap() { # состояние, число снимков
  for i in $(seq 1 $2); do
    for n in 11 12; do echo "$1 .$n $(ssh -o ConnectTimeout=4 root@$(node $n) "$SNAP")" >> $OUT; done
    sleep 1
  done
}
: > $OUT; echo "# регистры: $REGS" >> $OUT
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || { echo "# станция не подключилась" >> $OUT; exit 1; }
sleep 30
snap link 5
ssh root@$NODE_AP 'iperf3 -s -D >/dev/null 2>&1'; sleep 1
ssh root@$NODE_STA 'iperf3 -c 192.168.60.1 -t 25 >/dev/null 2>&1' & sleep 5
snap iperf 5
wait
ssh root@$NODE_STA 'wpa_cli -i phy0-sta0 disconnect >/dev/null 2>&1'; sleep 5
snap disc 5
ssh root@$NODE_STA 'wpa_cli -i phy0-sta0 reconnect >/dev/null 2>&1'
echo "# готово" >> $OUT
