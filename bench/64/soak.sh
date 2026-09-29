#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# soak.sh — долгая проверка пары AP + STA (прошивка 6.4, в первую очередь lite).
#
#   soak.sh BOOTS HOURS [журнал]
#
# 1. BOOTS загрузок: оба узла питанием; время до подключения станции,
#    iperf3 по 20 с в обе стороны, пинг 200, разрывы и сбросы прошивки.
# 2. HOURS часов без перезагрузки: циклы iperf3 60 с (попеременно в обе
#    стороны) + пинг 100; после каждого цикла — счётчики разрывов, сбросов
#    прошивки и сторожа по dmesg обоих узлов.
# Узлы и розетки — из окружения: NODE_AP, NODE_STA, TAPO_AP, TAPO_STA.
: "${NODE_AP:?}" "${NODE_STA:?}" "${TAPO_AP:?}" "${TAPO_STA:?}"
BOOTS=${1:-10}; HOURS=${2:-1}; LOG=${3:-soak-$(date +%Y%m%d-%H%M).log}
SPARRAW=${SPARRAW:-$(cd "$(dirname "$0")/../../.." && pwd)}
TAPO=$SPARRAW/SparRAW-tools/host/tapo_plug.py
SSH="ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no"
AP_IP=192.168.60.1

log() { echo "$(date +%T) $*" | tee -a "$LOG"; }

# счётчики по dmesg узла: разрывы после старта, восстановления fw, ошибки fw
counters() {
	$SSH root@$1 'd=$(dmesg); echo "disc=$(echo "$d" | awk -F"[][ ]+" "/_wil6210_disconnect:/ && \$2>40" | wc -l)" \
	  "recov=$(echo "$d" | grep -cE "recovering|fw error recovery")" \
	  "fwerr=$(echo "$d" | grep -ciE "firmware error|fw error|assert")" \
	  "up=$(cut -d. -f1 /proc/uptime)"' 2>/dev/null || echo "НЕДОСТУПЕН"
}

wait_link() {
	local t0=$(date +%s)
	for i in $(seq 1 90); do
		$SSH root@$NODE_STA 'dmesg | grep -q "successful connection"' 2>/dev/null && { echo $(( $(date +%s) - t0 )); return 0; }
		sleep 2
	done
	echo FAIL; return 1
}

iperf_pair() {   # $1: пусто — станция → AP, -R — AP → станция
	$SSH root@$NODE_AP '(setsid iperf3 -s -D </dev/null >/dev/null 2>&1 &)' 2>/dev/null
	$SSH root@$NODE_STA "iperf3 -c $AP_IP -t ${2:-20} $1 -i 0 2>&1 | awk '/receiver/{v=\$7; if (\$8 ~ /^G/) v*=1000; printf \"%d\", v}'" 2>/dev/null
}

ping_loss() {
	$SSH root@$NODE_STA "ping -c ${1:-200} -W 1 -q $AP_IP 2>&1 | grep -o '[0-9]*% packet loss'" 2>/dev/null
}

log "=== soak: загрузок $BOOTS, часов $HOURS; прошивка: $($SSH root@$NODE_AP 'dmesg | grep -o "FW ver. [^ (]*" | tail -1')"
for b in $(seq 1 $BOOTS); do
	python3 $TAPO $TAPO_AP cycle 15 >/dev/null & python3 $TAPO $TAPO_STA cycle 15 >/dev/null; wait
	sleep 20
	t=$(wait_link)
	up=$(iperf_pair "" 20); down=$(iperf_pair -R 20); loss=$(ping_loss 200)
	log "загрузка $b: линк за ${t} с после старта опроса, вверх ${up:-—} Мбит/с, вниз ${down:-—} Мбит/с, пинг ${loss:-—} | AP $(counters $NODE_AP) | STA $(counters $NODE_STA)"
done

end=$(( $(date +%s) + HOURS * 3600 )); n=0
log "=== длинный прогон"
while [ $(date +%s) -lt $end ]; do
	n=$((n+1)); dir=""; [ $((n % 2)) = 0 ] && dir=-R
	r=$(iperf_pair "$dir" 60); loss=$(ping_loss 100)
	log "цикл $n ${dir:-up}: ${r:-—} Мбит/с, пинг ${loss:-—} | AP $(counters $NODE_AP) | STA $(counters $NODE_STA)"
done
log "=== конец"
