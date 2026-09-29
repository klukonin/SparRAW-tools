#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# ctsexp.sh CFG — перезагрузка обоих, подключение, затем счётчики CTS/NAV на обоих узлах
# (navc.sh) до и после 20 с аплинк-пинга
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix; CFG=${1:-wap60g}
for h in 11 12; do timeout 15 ssh root@$(node $h) "cp /lib/firmware/wil6210.brd.$CFG /lib/firmware/wil6210.brd; sync"; done
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 60 >/dev/null
timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || { timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 60 >/dev/null; timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done'; }
sleep 10
for h in 11 12; do timeout 20 scp -O $B/navc.sh root@$(node $h):/tmp/navc.sh >/dev/null; done
echo "### $CFG до"; for h in 11 12; do echo ".$h $(timeout 10 ssh root@$(node $h) 'sh /tmp/navc.sh')"; done
timeout 40 ssh root@$NODE_STA 'ping -q -c 20 -W 1 192.168.60.1 | tail -2'
echo "### $CFG после"; for h in 11 12; do echo ".$h $(timeout 10 ssh root@$(node $h) 'sh /tmp/navc.sh')"; done
