#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# regfast.sh ТЕГ — быстрые серии TSF 0x886eb8, 0x886ec0, 0x886fc4/c8, NAV 0x886e84
# (по 40 троек подряд в одном шелле узла) после перезагрузки обоих узлов питанием.
cd "$SPARRAW"
T=${1:-regfast}; OUT=SparRAW-firmware/6.2/build/bench-62-mix/regfast_$T.log
SER='D=/sys/kernel/debug/ieee80211/phy0/wil6210; r(){ echo $1 > $D/mem_addr; v=$(cat $D/mem_val); echo -n "${v##*= } "; }; i=0; while [ $i -lt 40 ]; do r 0x886eb8; r 0x886ec0; r 0x886eb8; r 0x886fc4; r 0x886e84; echo; i=$((i+1)); done'
: > $OUT
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || { echo "# станция не подключилась" >> $OUT; exit 1; }
sleep 30
for n in 11 12; do ssh root@$(node $n) "$SER" | sed "s/^/.$n /" >> $OUT; done
echo "# готово" >> $OUT
