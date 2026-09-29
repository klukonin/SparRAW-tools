#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# flapcap.sh — перезагрузка обоих узлов и дампы кольца fw (blob_fw_peri) раз в
# секунду в /tmp/fc/ на каждом узле в течение N с (флаппинг первых минут)
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix; N=${1:-150}
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
for h in 11 12; do
 ( timeout 200 sh -c "until ssh -o ConnectTimeout=3 root@$(node $h) true 2>/dev/null; do sleep 2; done"
   timeout $((N+30)) ssh root@$(node $h) "D=/sys/kernel/debug/ieee80211/phy0/wil6210; mkdir -p /tmp/fc; until [ -e \$D/mem_write ] && [ \"\$(cat \$D/RGF_USER_USAGE_1 2>/dev/null)\" = 0x00843900 ]; do sleep 1; done; echo \"0x90b904 0x07010707\" > \$D/mem_write; echo \"0x90b908 0x07070701\" > \$D/mem_write; cut -d\" \" -f1 /proc/uptime > /tmp/fc/mute; i=0; while [ \$i -lt $N ]; do [ -e \$D/blob_fw_peri ] && { cut -d' ' -f1 /proc/uptime > /tmp/fc/t\$i; cat \$D/blob_fw_peri > /tmp/fc/p\$i.bin; cat \$D/RGF_USER_USAGE_1 > /tmp/fc/a\$i 2>/dev/null; }; i=\$((i+1)); sleep 1; done; dmesg > /tmp/fc/dmesg; cat /proc/uptime > /tmp/fc/end"
   mkdir -p $B/fc$h; rm -f $B/fc$h/*; timeout 120 scp -O -r root@$(node $h):/tmp/fc/* $B/fc$h/ >/dev/null ) &
done
wait; ls $B/fc11 | wc -l; ls $B/fc12 | wc -l
