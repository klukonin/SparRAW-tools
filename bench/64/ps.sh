#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# ps.sh — энергосбережение без графика (802.11-2020 11.2.7.2.2) в прошивке
# 6.4 apsta: станция засыпает по простою после `iw set power_save on`, точка
# видит это (маска спящих, UPSIM в маяке), станция просыпается по ATIM
# (нисходящий трафик) и по своим данным (восходящий).
#
# Ячейки ucode (окно данных для хоста 0x94xxxx): 0x9430f8 upm_vector (точка:
# спящие CID), 0x9430f9 in_doze (станция), 0x9430e4 upm_enable.
# Адреса — из окружения: NODE_AP, NODE_STA.  Перед опытом узлы перезагрузить.
set -u
: "${NODE_AP:?}" "${NODE_STA:?}"
DBG=/sys/kernel/debug/ieee80211/phy0/wil6210
AP_IP=192.168.60.1; STA_IP=192.168.60.2

run() { timeout 60 ssh -o ConnectTimeout=5 root@"$1" "$2"; }
rd() { run "$1" "echo $2 > $DBG/mem_addr; cat $DBG/mem_val" | sed 's/.*= //'; }
state() {
	echo "  STA: upm_enable/in_doze слово 0x9430e4=$(rd "$NODE_STA" 0x9430e4) 0x9430f8=$(rd "$NODE_STA" 0x9430f8);" \
	     "AP: upm_vector слово 0x9430f8=$(rd "$NODE_AP" 0x9430f8)"
}
sta_if() { run "$NODE_STA" "iw dev | awk '/Interface/{print \$2; exit}'"; }

IF=$(sta_if)
echo "== до: power_save $(run "$NODE_STA" "iw dev $IF get power_save")"; state
run "$NODE_STA" "iw dev $IF set power_save on; iw dev $IF get power_save"
sleep 5; echo "== 5 с простоя"; state
echo "== нисходящий пинг (станция должна проснуться по ATIM)"
run "$NODE_AP" "ping -c 10 -i 1 -W 2 $STA_IP | tail -3"
state
sleep 5; echo "== снова простой 5 с"; state
echo "== восходящий пинг (станция просыпается по своим данным)"
run "$NODE_STA" "ping -c 10 -i 1 -W 2 $AP_IP | tail -3"
sleep 5
echo "== iperf3 вверх при включённом PS"
run "$NODE_AP" "(setsid iperf3 -s -D </dev/null >/dev/null 2>&1 &); sleep 1"
run "$NODE_STA" "iperf3 -c $AP_IP -t 10 -i 0 2>&1 | grep receiver"
run "$NODE_STA" "iw dev $IF set power_save off; iw dev $IF get power_save"
sleep 3; echo "== после power_save off"; state
for n in "$NODE_AP" "$NODE_STA"; do
	run "$n" "dmesg | grep -ciE 'fw error|sysassert|recovery|disconnect'" | sed "s/^/$n ошибок и разрывов: /"
done
