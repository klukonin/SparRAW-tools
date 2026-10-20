#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# корень с соседними репозиториями SparRAW-*
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
: "${TAPO_AP:?задай TAPO_AP — адрес розетки узла AP}" "${TAPO_STA:?задай TAPO_STA — адрес розетки узла STA}"
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# regpoke.sh ТЕГ УЗЕЛ "РЕГ=ЗНАЧ ..." — опыт с вмешательством в регистр MAC.
# Питание обоих узлов -> линк -> замер «база» -> mem_write на УЗЕЛ (11, 12 или both)
# -> замер «после». Замер: пинг 10×1 с, iperf вверх 8 с, темп CP-кадров станции
# (0x8839a8/с — маяки), ход TSF AP к /proc/uptime, разрывы станции, чтение регистров.
cd "$SPARRAW"
T=$1; N=$2; W=$3; OUT=SparRAW-firmware/6.2/build/bench-62-mix/regpoke.log
D=/sys/kernel/debug/ieee80211/phy0/wil6210
RD='r(){ echo $1 > '$D'/mem_addr; v=$(cat '$D'/mem_val); echo -n "${v##*= }"; }'
REGS=$(echo "$W" | tr ' ' '\n' | cut -d= -f1 | tr '\n' ' ')
meas() {
  L=$1
  s=$(ssh root@$NODE_STA "$RD; a=\$(r 0x8839a8); u0=\$(cut -d' ' -f1 /proc/uptime); sleep 5; b=\$(r 0x8839a8); u1=\$(cut -d' ' -f1 /proc/uptime); echo \"\$a \$b \$u0 \$u1\"")
  set -- $s; cp=$(echo "$1 $2 $3 $4" | awk '{printf "%.1f", (strtonum($2)-strtonum($1))/($4-$3)}')
  t=$(ssh root@$NODE_AP "$RD; a=\$(r 0x886eb8); u0=\$(cut -d' ' -f1 /proc/uptime); sleep 10; b=\$(r 0x886eb8); u1=\$(cut -d' ' -f1 /proc/uptime); echo \"\$a \$b \$u0 \$u1\"")
  set -- $t; ppm=$(echo "$1 $2 $3 $4" | awk '{d=(strtonum($2)-strtonum($1)); if(d<0)d+=4294967296; printf "%.4f", d/(($4-$3)*1e6)}')
  p=$(ssh root@$NODE_STA 'ping -q -c 10 -W 1 192.168.60.1 | tail -2 | tr "\n" " "' | grep -oE '[0-9]+% packet loss|= [0-9./]+' | tr '\n' ' ')
  ip=""; k=0; while [ $k -lt ${IPN:-1} ]; do ip="$ip$(ssh root@$NODE_STA 'iperf3 -c 192.168.60.1 -t 8 2>&1 | grep receiver | grep -oE "[0-9.]+ [MG]bits/sec"') "; k=$((k+1)); done
  dc=$(ssh root@$NODE_STA 'dmesg | grep -c wmi_evt_disconnect')
  rb=""; for g in $REGS; do case $N in 12) h=12;; *) h=11;; esac; rb="$rb $g=$(ssh root@$(node $h) "$RD; r $g")"; [ "$N" = both ] && rb="$rb/$(ssh root@$NODE_STA "$RD; r $g")"; done
  echo "$T $L: пинг [$p] iperf [$ip] CP/с $cp TSF/сек_узла $ppm разрывов $dc |$rb" >> $OUT
}
echo "## $T $(date +%T) узел $N: $W" >> $OUT
timeout 40 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_AP" cycle 15 >/dev/null
timeout 90 python3 SparRAW-tools/host/tapo_plug.py "$TAPO_STA" cycle 30 >/dev/null
timeout 300 sh -c 'until ssh -o ConnectTimeout=4 root@$NODE_STA "iw dev phy0-sta0 link 2>/dev/null | grep -q Connected" 2>/dev/null; do sleep 5; done' || { echo "# $T: станция не подключилась" >> $OUT; exit 1; }
ssh root@$NODE_AP 'iperf3 -s -D >/dev/null 2>&1'
sleep 25
meas база
for h in 11 12; do
  case $N in both|$h) ssh root@$(node $h) "for kv in $W; do echo \"\${kv%%=*} \${kv#*=}\" > $D/mem_write; done";; esac
done
sleep 3
meas после
sleep 20
meas после+20с
