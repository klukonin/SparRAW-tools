#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# atimdiag.sh — почему точка не шлёт ATIM станции в UPM-doze (6.4 apsta).
#
# Станция: `iw set power_save on`, простой до doze.  Точка: пинг на станцию
# 10 с; раз в секунду на точке читаются (окно данных ucode для хоста):
#   0x943118  счётчики источников collect_awake_peers по CID 0..3
#   0x91f03c/0x91f040  отладочная пара последнего AW
#   0x942f68  вектор целей ATIM после AW
#   0x9430a8  ctx+0x128 (peer_eligibility), +0x129
#   0x942194  CID с поддержанием связи
#   0x9430f8  upm_vector (спящие)
#   0x881c84  кольца TX с дескрипторами
# и кольца debugfs.  В конце — MAC_MON AW точки.
# Адреса — из окружения: NODE_AP, NODE_STA.  Перед опытом узлы перезагрузить.
set -u
: "${NODE_AP:?}" "${NODE_STA:?}"
DBG=/sys/kernel/debug/ieee80211/phy0/wil6210
run() { timeout 60 ssh -o ConnectTimeout=5 root@"$1" "$2"; }
rd() { run "$1" "for a in $2; do echo \$a > $DBG/mem_addr; sed 's/.*= //' $DBG/mem_val; done" | tr '\n' ' '; }
ADDRS="0x943118 0x91f03c 0x91f040 0x942f68 0x9430a8 0x942194 0x9430f8 0x881c84"

IF=$(run "$NODE_STA" "iw dev | awk '/Interface/{print \$2; exit}'")
run "$NODE_STA" "iw dev $IF set power_save on"; sleep 6
echo "STA in_doze слово 0x9430f8: $(rd "$NODE_STA" 0x9430f8)"
echo "адреса: $ADDRS"
echo "до пинга:  $(rd "$NODE_AP" "$ADDRS")"
run "$NODE_AP" "ping -c 10 -W 1 192.168.60.2 >/tmp/p.txt 2>&1 &" 
for i in $(seq 1 8); do sleep 1; echo "пинг +$i с: $(rd "$NODE_AP" "$ADDRS")"; done
sleep 3; run "$NODE_AP" "tail -2 /tmp/p.txt"
run "$NODE_AP" "cat $DBG/rings | head -20"
run "$NODE_STA" "iw dev $IF set power_save off"
