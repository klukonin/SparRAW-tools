#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# flaptrig.sh [N] — триггерная съёмка кольца fw на станции (.12) и AP (.11):
# по кругу 300 дампов кольца (dd, ~4 с истории); раз в 20 дампов проверяется
# dmesg; после N-го разрыва (wmi_evt_disconnect) снимаем ещё 40 дампов и стоп.
# Узлы НЕ перезагружает (запускать после перезагрузки, до первого разрыва).
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix; N=${1:-1}
for h in 11 12; do
 ( timeout 900 ssh root@$(node $h) "D=/sys/kernel/debug/ieee80211/phy0/wil6210; rm -rf /tmp/ft; mkdir -p /tmp/ft
     until [ -e \$D/mem_write ] && [ \"\$(cat \$D/RGF_USER_USAGE_1 2>/dev/null)\" = 0x00843900 ]; do sleep 1; done
     echo '0x90b904 0x07010707' > \$D/mem_write; echo '0x90b908 0x07070701' > \$D/mem_write
     b=\$(dmesg | grep -c wmi_evt_disconnect); i=0; stop=-1
     while :; do k=\$((i%300)); dd if=\$D/blob_fw_peri bs=256 skip=57 count=34 of=/tmp/ft/r\$k 2>/dev/null; echo \"\$i \$k \$(cut -d' ' -f1 /proc/uptime)\" >> /tmp/ft/idx
       i=\$((i+1))
       if [ \$stop -lt 0 ] && [ \$((i%20)) = 0 ] && [ \$(dmesg | grep -c wmi_evt_disconnect) -ge \$((b+$N)) ]; then stop=\$((i+40)); fi
       [ \$stop -ge 0 ] && [ \$i -ge \$stop ] && break
     done; dmesg > /tmp/ft/dmesg; tail -300 /tmp/ft/idx > /tmp/ft/idx2"
   mkdir -p $B/ft$h; rm -f $B/ft$h/*; ssh root@$(node $h) 'cd /tmp/ft && tar cf - r* idx2 dmesg' | tar xf - -C $B/ft$h ) &
done
wait; wc -l $B/ft11/idx2 $B/ft12/idx2
