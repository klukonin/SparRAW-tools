#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# rtxss.sh [РАЗ] — SLS в DTI по команде хоста: работает ли ответчик R-TXSS.
#
# При поднятом линке AP↔STA каждый узел по очереди РАЗ раз (по умолчанию 20)
# запускает SLS к соседу командой WMI_BF_TRIG (0x83a, bf_type 0 = SLS) через
# debugfs wmi_send; сосед при этом — ответчик R-TXSS (802.11-2020 10.42.2).
# Исходы — по кольцу ucode (uc_trace) за окно опыта: состояния BF
# «STATE:SUBSTATE» (3:x — инициатор TXSS, 4:9 — ответчик успешно, 4:10 — нет
# SSW-Feedback, 4:11 — отказ ответчика).  Затем пинг и iperf3 — линк жив.
#
# Адреса — из окружения: NODE_AP, NODE_STA.  Перед опытом узлы перезагрузить.
set -u
: "${NODE_AP:?}" "${NODE_STA:?}"
N=${1:-20}
HERE=$(cd "$(dirname "$0")" && pwd)
SPARRAW=$(cd "$HERE/../../.." && pwd)
FW=$SPARRAW/SparRAW-firmware/6.2
OUT=$(mktemp -d)
DBG=/sys/kernel/debug/ieee80211/phy0/wil6210
WMI_BF_TRIG=0x083a

run() { timeout 30 ssh -o ConnectTimeout=5 root@"$1" "$2"; }
mac() { run "$1" "cat /sys/class/net/\$(ls /sys/class/net | grep -m1 -E 'wlan|phy0')/address"; }

# wmi_send: заголовок {mid, 0, u16 id, u32 0} + тело {bf_type 0, cid 0, mac[6], 0[4]}
bf_trig_hex() {
	local m=${1//:/}
	printf '\\x00\\x00\\x%02x\\x%02x\\x00\\x00\\x00\\x00\\x00\\x00' $((WMI_BF_TRIG & 0xff)) $((WMI_BF_TRIG >> 8))
	for i in 0 2 4 6 8 10; do printf '\\x%s' "${m:$i:2}"; done
	printf '\\x00\\x00\\x00\\x00'
}

MAC_AP=$(mac "$NODE_AP"); MAC_STA=$(mac "$NODE_STA")
echo "AP $NODE_AP $MAC_AP, STA $NODE_STA $MAC_STA"
t_ap=$(run "$NODE_AP" 'cut -d" " -f1 /proc/uptime'); t_sta=$(run "$NODE_STA" 'cut -d" " -f1 /proc/uptime')

for dir in "STA→AP:$NODE_STA:$MAC_AP" "AP→STA:$NODE_AP:$MAC_STA"; do
	IFS=: read -r name node peer <<<"$dir"
	hex=$(bf_trig_hex "$peer")
	run "$node" "for i in \$(seq $N); do printf '$hex' > /tmp/wmi.bin; dd if=/tmp/wmi.bin of=$DBG/wmi_send bs=20 count=1 2>/dev/null; sleep 1; done"
	echo "$name: $N команд SLS отправлено"
	sleep 2
done

for n in "$NODE_AP:$t_ap" "$NODE_STA:$t_sta"; do
	IFS=: read -r h s <<<"$n"
	run "$h" "cut -d' ' -f1 /proc/uptime; cat $DBG/uc_trace" > "$OUT/$h.raw"
	e=$(head -1 "$OUT/$h.raw")
	tail -c +$(( $(head -1 "$OUT/$h.raw" | wc -c) + 1 )) "$OUT/$h.raw" > "$OUT/$h.bin"
	echo "== $h: исходы BF за окно $s..$e"
	python3 "$SPARRAW/SparRAW-tools/host/wil_uc_collect.py" "$OUT/$h.bin" -s "$FW/ref/strings-uc.bin" \
		--raw --since "$s" --until "$e" |
		grep -oE "bf_sm_handler in state:[0-9]+:[0-9]+|triggers:[0-9]+" | sort | uniq -c | sort -rn | head -12
	run "$h" "dmesg | grep -E '0x083a|disconnect' | tail -3"
done
run "$NODE_STA" "ping -q -c 20 -W 1 192.168.60.1 | tail -2"
rm -rf "$OUT"
