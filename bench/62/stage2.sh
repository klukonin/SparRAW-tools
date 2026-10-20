#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
cd "$SPARRAW/SparRAW-firmware/6.2"
P=../../SparRAW-tools/bench/62/regpoke.sh
../../SparRAW-tools/bench/62/navtest.sh
IPN=3 $P de8_half_r 11 "0x886de8=0x00060012"
IPN=3 $P de8_double 11 "0x886de8=0x0006004a"
$P d44_nob4  11 "0x886d44=0x00028000"
$P d44_nob15 11 "0x886d44=0x00020010"
$P d44_nob17 11 "0x886d44=0x00008010"
$P d40_nob0  11 "0x886d40=0x00ffff00"
$P d40_nob1  11 "0x886d40=0x00ff00ff"
$P d40_nob2  11 "0x886d40=0x0000ffff"
cd "$SPARRAW"
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
echo "# этап 2 готов $(date +%T), узлы перезагружены" >> SparRAW-firmware/6.2/build/bench-62-mix/regpoke.log
