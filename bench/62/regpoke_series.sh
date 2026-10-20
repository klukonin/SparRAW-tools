#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
cd "$SPARRAW/SparRAW-firmware/6.2"
P=../../SparRAW-tools/bench/62/regpoke.sh
: > build/bench-62-mix/regpoke.log
$P d20_100   11   "0x886d20=0x64"
$P d20_0     11   "0x886d20=0x0"
$P d24_0     11   "0x886d24=0x0"
$P d14_150   12   "0x886d14=0x96"
$P d14_4000  12   "0x886d14=0xfa0"
$P d14_64    both "0x886d14=0x40"
$P f60_200   both "0x886f60=0x00c800c8"
$P f60_4095  both "0x886f60=0x0fff0fff"
$P d5c_half  11   "0x886d5c=0x00040031"
$P d60_2     11   "0x886d60=0x00020002"
$P de8_half  11   "0x886de8=0x00060012"
$P dec_half  11   "0x886dec=0x00020005"
$P d40_0     11   "0x886d40=0x0"
$P d44_0     11   "0x886d44=0x0"
$P fc0_0     11   "0x886fc0=0x0"
cd "$SPARRAW"
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
echo "# готово $(date +%T), узлы перезагружены" >> SparRAW-firmware/6.2/build/bench-62-mix/regpoke.log
