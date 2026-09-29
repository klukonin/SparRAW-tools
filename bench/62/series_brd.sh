#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# series_brd.sh — чередование board: для каждой конфигурации перезагрузка обоих узлов
# (правило стенда), ожидание подключения STA, два окна bfmeasure по 30 с.
cd "$SPARRAW"
B=SparRAW-firmware/6.2/build/bench-62-mix
run=0
for cfg in ${CFGS:-wap60g f35 wap60g f35}; do
  run=$((run+1))
  for h in 11 12; do timeout 15 ssh root@$(node $h) "cp /lib/firmware/wil6210.brd.$cfg /lib/firmware/wil6210.brd; sync"; done
  timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
  timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 60 >/dev/null
  if ! timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done'; then
    echo "### run$run $cfg: STA не подключилась (возможно, завис .12) — повтор питания"
    timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 60 >/dev/null
    timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || { echo "### run$run $cfg: пропуск"; continue; }
  fi
  sleep 10
  echo "### run$run $cfg brd=$(timeout 8 ssh root@$NODE_AP 'md5sum /lib/firmware/wil6210.brd' | cut -c1-8)"
  for h in 11 12; do timeout 10 ssh root@$(node $h) "cat /sys/kernel/debug/ieee80211/phy0/wil6210/blob_fw_data" > /tmp/fd_$h.bin; python3 -c "d=open(\"/tmp/fd_$h.bin\",\"rb\").read(); n=d[0x42cc+0x40]; print(\"### .$h brd_if n=\",n,d[0x42cc:0x42cc+n].hex())"; done
  for w in 1 2; do timeout 120 $B/bfmeasure.sh s${run}_${cfg}_$w 30 2>/dev/null; done
done
echo "### ГОТОВО"
