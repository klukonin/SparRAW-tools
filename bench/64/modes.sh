#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# modes.sh — режимы прошивки 6.4 apsta: PBSS работает, DMG IBSS отвергается.
#
# Опыт 1 (PBSS): узел NODE_AP — PCP (hostapd с pbss=1), узел NODE_STA —
# станция PBSS (wpa_supplicant с pbss=1); ждём соединения, пинг и iperf3.
# Опыт 2 (IBSS): оба узла `iw ibss join`; прошивка apsta должна отвергнуть
# старт (в журнале ядра — отказ PCP start, маяков нет).
# Перед каждым опытом и в конце оба узла перезагружаются питанием — после
# этого OpenWrt снова поднимает обычные AP и STA из /etc/config/wireless.
#
# Адреса — из окружения: NODE_AP, NODE_STA, TAPO_AP, TAPO_STA.
set -u
: "${NODE_AP:?}" "${NODE_STA:?}" "${TAPO_AP:?}" "${TAPO_STA:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
TAPO=$HERE/../../host/tapo_plug.py

run() { timeout 60 ssh -o ConnectTimeout=5 root@"$1" "$2"; }

power_cycle() {
	python3 "$TAPO" "$TAPO_AP" cycle 15 >/dev/null & python3 "$TAPO" "$TAPO_STA" cycle 15 >/dev/null; wait
	for n in "$NODE_AP" "$NODE_STA"; do
		for i in $(seq 1 60); do run "$n" true 2>/dev/null && break; sleep 3; done
		for i in $(seq 1 30); do run "$n" "iw dev | grep -q Interface" && break; sleep 2; done
	done
	sleep 10
}

wifi_if() { run "$1" "iw dev | awk '/Interface/{print \$2; exit}'"; }

echo "=== опыт 1: PBSS"
power_cycle
IF_A=$(wifi_if "$NODE_AP"); IF_B=$(wifi_if "$NODE_STA")
# Сначала `wifi down`: иначе netifd раз в 30 с повторяет настройку радио и
# через ubus велит hostapd (сборка OpenWrt, даже запущенная вручную)
# «Remove interface 'phy0'» — PCP пропадает.  Затем wpad stop и пауза.
for n in "$NODE_AP" "$NODE_STA"; do run "$n" "wifi down; sleep 5; /etc/init.d/wpad stop"; done; sleep 40
run "$NODE_AP" "
	ip link set $IF_A down; iw dev $IF_A set type ap; ip link set $IF_A up
	M=\$(cat /sys/class/net/$IF_A/address)
	printf 'driver=nl80211\nbeacon_int=100\nhw_mode=ad\nchannel=1\nstationary_ap=1\ninterface=$IF_A\nbssid=%s\nssid2=\"PBSS60\"\nctrl_interface=/var/run/hostapd-pbss\nwpa=0\npbss=1\n' \$M > /tmp/pbss.conf
	hostapd -B /tmp/pbss.conf; sleep 2; ip addr add 192.168.61.1/24 dev $IF_A"
run "$NODE_STA" "dmesg -c >/dev/null
	ip link set $IF_B down; iw dev $IF_B set type managed; ip link set $IF_B up
	printf 'ctrl_interface=/var/run/wpa_supplicant-pbss\nnetwork={\n\tssid=\"PBSS60\"\n\tkey_mgmt=NONE\n\tpbss=1\n}\n' > /tmp/wpa-pbss.conf
	wpa_supplicant -B -i $IF_B -c /tmp/wpa-pbss.conf; ip addr add 192.168.61.2/24 dev $IF_B"
ok=0
for i in $(seq 1 30); do
	run "$NODE_STA" "dmesg | grep -q 'successful connection'" && { ok=1; break; }; sleep 3
done
echo "PBSS: соединение $([ $ok = 1 ] && echo есть || echo НЕТ)"
run "$NODE_STA" "dmesg | grep -E 'PBSS: |successful connection|assoc' | tail -4"
if [ $ok = 1 ]; then
	run "$NODE_STA" "ping -q -c 20 -W 1 192.168.61.1 | tail -2"
	run "$NODE_AP" "(setsid iperf3 -s -D </dev/null >/dev/null 2>&1 &); sleep 1"
	run "$NODE_STA" "iperf3 -c 192.168.61.1 -t 10 -i 0 2>&1 | grep receiver; iperf3 -c 192.168.61.1 -t 10 -i 0 -R 2>&1 | grep receiver"
	run "$NODE_STA" "dmesg | grep -cE 'wmi_evt_disconnect'" | sed 's/^/разрывов PBSS: /'
fi
for n in "$NODE_AP" "$NODE_STA"; do run "$n" "dmesg | grep -ciE 'fw error|sysassert|recovery'" | sed "s/^/$n ошибок fw: /"; done

echo "=== опыт 2: DMG IBSS (должен быть отказ)"
power_cycle
for n in "$NODE_AP" "$NODE_STA"; do
	IF=$(wifi_if "$n")
	run "$n" "wifi down; sleep 5; /etc/init.d/wpad stop; sleep 5; ip link set $IF down; iw dev $IF set type ibss; ip link set $IF up
		iw dev $IF ibss join MESH60 58320 fixed-freq 02:60:ad:00:00:01; echo \"join rc=\$?\""
done
sleep 10
for n in "$NODE_AP" "$NODE_STA"; do
	echo "-- $n"; run "$n" "dmesg | grep -iE 'ibss|pcp_start|pcp start|PCP_STARTED|refused' | tail -4"
	run "$n" "dmesg | grep -ciE 'fw error|sysassert|recovery'" | sed 's/^/ошибок fw: /'
done

echo "=== возврат к обычной конфигурации"
power_cycle
for i in $(seq 1 40); do run "$NODE_STA" "dmesg | grep -q 'successful connection'" && { echo "линк AP-STA поднят"; break; }; sleep 3; done
