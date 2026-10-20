#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# rxfreeze.sh [СЕК] [ПЛАТА] — перезагрузка обоих; затем раз в 2 с на AP и STA:
# uptime, 0x942304 (счётчик взводов приёма ucode), 0x943234 (указатель лога
# ucode), 0x9422d4 (TX-векторы), число wmi_evt_disconnect.
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix; N=${1:-300}
CFG=${2:-wap60g}; for h in 11 12; do timeout 15 ssh root@$(node $h) "cp /lib/firmware/wil6210.brd.$CFG /lib/firmware/wil6210.brd; sync"; done
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
for h in 11 12; do
 ( timeout 200 sh -c "until ssh -o ConnectTimeout=3 root@$(node $h) true 2>/dev/null; do sleep 2; done"
   timeout $((N+120)) ssh root@$(node $h) "D=/sys/kernel/debug/ieee80211/phy0/wil6210
     until [ -e \$D/mem_addr ] && [ \"\$(cat \$D/RGF_USER_USAGE_2 2>/dev/null)\" = 0x00803234 ]; do sleep 1; done
     i=0; while [ \$i -lt $((N/2)) ]; do
       l=\"\$(cut -d' ' -f1 /proc/uptime)\"
       for a in 0x942304 0x943234 0x9422d4; do echo \$a > \$D/mem_addr; v=\$(cat \$D/mem_val); l=\"\$l \${v##*= }\"; done
       echo \"\$l \$(dmesg | grep -c wmi_evt_disconnect)\"; i=\$((i+1)); sleep 2; done" > $B/rxf_$h.log ) &
done
wait; tail -3 $B/rxf_11.log $B/rxf_12.log
