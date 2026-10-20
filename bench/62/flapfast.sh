#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# flapfast.sh — перезагрузка обоих узлов; на станции (.12) глушим MAC_MON/PHY_MON
# и с первого подключения 8 с подряд снимаем только кольцо fw (dd 8,5 КБ по
# смещению 0x3900 в blob_fw_peri) без пауз; на AP то же параллельно.
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix; W=${1:-8}
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
for h in 11 12; do
 ( timeout 200 sh -c "until ssh -o ConnectTimeout=3 root@$(node $h) true 2>/dev/null; do sleep 2; done"
   timeout 400 ssh root@$(node $h) "D=/sys/kernel/debug/ieee80211/phy0/wil6210; rm -rf /tmp/ff; mkdir -p /tmp/ff
     until [ -e \$D/mem_write ] && [ \"\$(cat \$D/RGF_USER_USAGE_1 2>/dev/null)\" = 0x00843900 ]; do sleep 1; done
     echo '0x90b904 0x07010707' > \$D/mem_write; echo '0x90b908 0x07070701' > \$D/mem_write
     until dmesg | grep -q 'successful connection'; do sleep 1; done
     s=\$(cut -d' ' -f1 /proc/uptime); i=0
     while :; do t=\$(cut -d' ' -f1 /proc/uptime); dd if=\$D/blob_fw_peri bs=256 skip=57 count=34 of=/tmp/ff/r\$i 2>/dev/null; echo \"\$i \$t\" >> /tmp/ff/idx; i=\$((i+1)); [ \$(( \${t%.*} - \${s%.*} )) -ge $W ] && break; done
     dmesg > /tmp/ff/dmesg"
   mkdir -p $B/ff$h; rm -f $B/ff$h/*; ssh root@$(node $h) 'cd /tmp/ff && tar cf - .' | tar xf - -C $B/ff$h ) &
done
wait; wc -l $B/ff11/idx $B/ff12/idx
