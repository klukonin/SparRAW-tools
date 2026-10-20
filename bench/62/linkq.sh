#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# linkq.sh ТЕГ FW12 — поставить на станцию (.12) образ /lib/firmware/FW12
# (на AP всегда wil6210.fw.62), перезагрузить оба, 60 с на установление,
# затем 10 пингов по 20 с со станции; итог — принято/200 и разрывы станции.
cd "$SPARRAW"
T=$1; FW=$2; FWAP=${3:-wil6210.fw.62}; BRD=${4:-wap60g}; IPERF=${5:-0}
ssh root@$NODE_AP "cp /lib/firmware/$FWAP /lib/firmware/wil6210.fw; cp /lib/firmware/wil6210.brd.$BRD /lib/firmware/wil6210.brd; sync"
ssh root@$NODE_STA "cp /lib/firmware/$FW /lib/firmware/wil6210.fw; cp /lib/firmware/wil6210.brd.$BRD /lib/firmware/wil6210.brd; sync; md5sum /lib/firmware/wil6210.brd; md5sum /lib/firmware/wil6210.fw"
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || echo "$T: станция не подключилась за 300 с"
sleep 60
ssh root@$NODE_STA "D=/sys/kernel/debug/ieee80211/phy0/wil6210; echo 0x941110 > \$D/mem_addr; cat \$D/mem_val; d0=\$(dmesg | grep -c wmi_evt_disconnect); s=''; t=0; i=0
  while [ \$i -lt 10 ]; do r=\$(ping -q -c 20 -W 1 192.168.60.1 | grep -oE '[0-9]+ packets received' | cut -d' ' -f1); s=\"\$s \$r\"; t=\$((t+r)); i=\$((i+1)); done
  echo \"$T: пинг\$s = \$t/200, разрывов за замер \$((\$(dmesg | grep -c wmi_evt_disconnect)-d0)), всего \$(dmesg | grep -c wmi_evt_disconnect)\"; echo 0x941110 > \$D/mem_addr; cat \$D/mem_val"
if [ "$IPERF" = 1 ]; then
  ssh root@$NODE_AP 'iperf3 -s -D >/dev/null 2>&1'; sleep 1
  ssh root@$NODE_STA "echo \"$T: iperf вверх \$(iperf3 -c 192.168.60.1 -t 20 | grep receiver | grep -oE '[0-9.]+ [MG]bits/sec'), вниз \$(iperf3 -c 192.168.60.1 -t 20 -R | grep receiver | grep -oE '[0-9.]+ [MG]bits/sec'), разрывов всего \$(dmesg | grep -c wmi_evt_disconnect)\""
fi
