#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# mesh.sh FW [СЕКУНД] — опыт прошивки 6.4 mesh (DMG IBSS) на двух узлах.
#
# Заливает образ FW на оба узла, передёргивает питание, переводит интерфейс
# в IBSS и присоединяет оба узла к одной ячейке с общим BSSID.  Затем
# снимает с обоих:
#   * BSSID в регистре MAC (0x886df0/0x886df4);
#   * состояние случайной задержки маяка 11.1.3.5 (struct ibss_uc_state,
#     host 0x943a4c): длительность BTI, BTI с развёрткой, отменённые BTI,
#     последняя задержка — два замера через СЕКУНД (по умолчанию 10);
#   * серию последних задержек (разброс должен быть в [0, 6·T_BTI]).
#
# Адреса стенда — из окружения: NODE_AP, NODE_STA (узлы A и B), TAPO_AP,
# TAPO_STA (их розетки).  Вернуть узлы в apsta: тот же приём с образом apsta
# и обычная загрузка (тип интерфейса после питания снова из конфигурации).
set -u
: "${NODE_AP:?}" "${NODE_STA:?}" "${TAPO_AP:?}" "${TAPO_STA:?}"
FW=${1:?образ прошивки mesh}
SEC=${2:-10}
HERE=$(cd "$(dirname "$0")" && pwd)
TAPO=$HERE/../../host/tapo_plug.py
SSID=MESH60
FREQ=58320
BSSID=02:60:ad:00:00:01
DBG=/sys/kernel/debug/ieee80211/phy0/wil6210
IBSS_UC=0x943a4c
# WMI 0x85a IBSS_BSSID: заголовок {mid 0, 0, u16 0x085a, u32 0} + {bssid[6], 0, 0}
CMD_85A='\x00\x00\x5a\x08\x00\x00\x00\x00'$(printf '\x%s' ${BSSID//:/ })'\x00\x00'

run() { timeout 20 ssh -o ConnectTimeout=5 root@"$1" "$2"; }

for n in "$NODE_AP" "$NODE_STA"; do
	scp -qO "$FW" root@"$n":/lib/firmware/wil6210.fw && run "$n" sync || exit 1
done
# розетки по очереди и с повтором: после частых входов Tapo на минуты отказывает
cycle() { local i; for i in $(seq 1 15); do python3 "$TAPO" "$1" cycle 15 >/dev/null 2>&1 && return 0; sleep 60; done
	echo "розетка $1 не отвечает" >&2; exit 1; }
cycle "$TAPO_AP"; cycle "$TAPO_STA"
for n in "$NODE_AP" "$NODE_STA"; do
	for i in $(seq 1 60); do run "$n" true 2>/dev/null && break; sleep 3; done
	for i in $(seq 1 20); do run "$n" "iw dev | grep -q Interface" && break; sleep 2; done
done

# Интерфейс в IBSS: сначала wifi down (иначе netifd раз в 30 с через ubus
# сносит интерфейс), затем wpad stop и пауза, пока уляжется.
for n in "$NODE_AP" "$NODE_STA"; do run "$n" "wifi down; sleep 5; /etc/init.d/wpad stop"; done
sleep 40
for n in "$NODE_AP" "$NODE_STA"; do
	run "$n" "
		IF=\$(iw dev | awk '/Interface/{print \$2; exit}')
		ip link set \$IF down; iw dev \$IF set type ibss; ip link set \$IF up
		# BSSID ячейки прошивке (WMI 0x85a) — сам, если драйвер без патча 917;
		# одной записью: printf BusyBox пишет в debugfs кусками
		printf '$CMD_85A' > /tmp/w.bin; dd if=/tmp/w.bin of=$DBG/wmi_send bs=16 count=1 2>/dev/null
		iw dev \$IF ibss join $SSID $FREQ fixed-freq $BSSID
		echo \"\$(hostname): \$IF \$(cat $DBG/fw_version)\""
	sleep 2
done

rd() { # rd УЗЕЛ АДРЕС [ЧИСЛО_СЛОВ] -> слова в hex через пробел
	local a=() i
	for ((i = 0; i < ${3:-1}; i++)); do a+=($(printf '0x%x' $(($2 + 4 * i)))); done
	run "$1" "for a in ${a[*]}; do echo \$a > $DBG/mem_addr
		sed -n 's/.*= *0x\([0-9a-fA-F]*\).*/\1/p' $DBG/mem_val; done" | tr '\n' ' '
}

state() { # state УЗЕЛ -> «bti sent cancelled delay» в десятичном виде
	set -- $(rd "$1" $IBSS_UC 4)
	printf '%d %d %d %d' $(( 0x$1 & 0xffff )) 0x$2 0x$3 0x$4
}

sleep 5
declare -A S0
for n in "$NODE_AP" "$NODE_STA"; do
	echo "== $n: BSSID в MAC $(rd "$n" 0x886df0 2)"
	S0[$n]=$(state "$n")
done
sleep "$SEC"
for n in "$NODE_AP" "$NODE_STA"; do
	read -r bti s0 c0 _ <<<"${S0[$n]}"
	read -r bti s1 c1 d <<<"$(state "$n")"
	echo "== $n: T_BTI $bti мкс; за $SEC с: с развёрткой $((s1 - s0)), отменено $((c1 - c0)); последняя задержка $d мкс (предел $((6 * bti)))"
done

echo "== задержки узла $NODE_AP (20 замеров):"
for i in $(seq 1 20); do state "$NODE_AP" | awk '{printf "%s ", $4}'; sleep 0.3; done; echo
for n in "$NODE_AP" "$NODE_STA"; do
	echo "== $n: dmesg"; run "$n" "dmesg | grep -iE 'ibss|wil6210.*(error|assert)' | tail -5"
done
