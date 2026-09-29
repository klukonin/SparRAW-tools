#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# ese.sh — расписание ESE точки и его соблюдение станцией (802.11-2020 10.39).
#
# При поднятом линке AP↔STA:
#  1) база: iperf3 вверх и вниз по 15 с;
#  2) точке задаётся расписание WMI_SCHEDULING_SCHEME (0xa01, через debugfs
#     wmi_send): CBAP 0xff→0xff [2, 30) мс, SP чужой паре 5→6 [32, 62) мс,
#     CBAP 0xff→0xff [64, 100) мс; ESE в маяке.  Маяк при этом идёт с
#     CBAP Only = 0 — станция 6.4 обязана остаться на связи;
#  3) снова iperf3: если станция соблюдает чужой SP, её восходящая скорость
#     падает примерно на долю SP (~30 %);
#  4) расписание снимается (флаги без ENABLE), линк проверяется.
#
# Адреса — из окружения: NODE_AP, NODE_STA.  Перед опытом узлы перезагрузить.
set -u
: "${NODE_AP:?}" "${NODE_STA:?}"
DBG=/sys/kernel/debug/ieee80211/phy0/wil6210
AP_IP=192.168.60.1

run() { timeout 60 ssh -o ConnectTimeout=5 root@"$1" "$2"; }
iperf() { run "$NODE_STA" "iperf3 -c $AP_IP -t 15 -i 0 $1 2>&1 | awk '/receiver/{v=\$7; if (\$8 ~ /^G/) v*=1000; printf \"%d\", v}'"; }

hex8()  { printf '\\x%02x' $(($1 & 0xff)); }
hex16() { hex8 $1; hex8 $(($1 >> 8)); }
hex32() { hex16 $(($1 & 0xffff)); hex16 $(($1 >> 16)); }
# слот: tbtt_offset u32, flags u8, type u8, duration u16, tx_op u16, period u16,
#       num_of_blocks u8, idle_period u8, src_aid u8, dest_aid u8, reserved u32
slot() { hex32 $1; hex8 0; hex8 $2; hex16 $3; hex16 0; hex16 0; hex8 1; hex8 0; hex8 $4; hex8 $5; hex32 0; }
# заголовок wmi_send: mid, 0, u16 id 0xa01, u32 0
sched_cmd() { # flags num слоты...
	local f=$1 n=$2; shift 2
	hex8 0; hex8 0; hex16 0xa01; hex32 0
	hex8 1; hex8 1; hex16 $f; hex8 $n; hex8 0; hex8 0; hex8 0; hex32 0; hex32 0
	printf '%s' "$@"
	for ((i = n; i < 4; i++)); do slot 0 0 0 0 0; done
}
SP=0; CBAP=1
SCHED=$(sched_cmd $((0x01 | 0x04 | 0x08 | 0x10)) 3 \
	"$(slot 2000 $CBAP 28000 255 255)" "$(slot 32000 $SP 30000 5 6)" "$(slot 64000 $CBAP 36000 255 255)")
CLEAR=$(sched_cmd $((0x04 | 0x08)) 0)

run "$NODE_AP" "(setsid iperf3 -s -D </dev/null >/dev/null 2>&1 &); sleep 1"
echo "база: вверх $(iperf '') Мбит/с, вниз $(iperf -R) Мбит/с"

# одной записью: printf BusyBox пишет кусками, а wmi_send берёт только
# запись с нулевого смещения
wmi() { run "$NODE_AP" "printf '$1' > /tmp/wmi.bin; dd if=/tmp/wmi.bin of=$DBG/wmi_send bs=\$(wc -c < /tmp/wmi.bin) count=1 2>/dev/null"; }
wmi "$SCHED"; sleep 3
run "$NODE_AP" "dmesg | grep -E 'wil_write_file_wmi' | tail -1"
echo "с расписанием: вверх $(iperf '') Мбит/с, вниз $(iperf -R) Мбит/с"
run "$NODE_STA" "iw dev \$(iw dev | awk '/Interface/{print \$2; exit}') link | head -3"
run "$NODE_STA" "dmesg | grep -cE 'disconnect'" | sed 's/^/разрывов у станции: /'

wmi "$CLEAR"; sleep 3
echo "после снятия: вверх $(iperf '') Мбит/с"
for n in "$NODE_AP" "$NODE_STA"; do run "$n" "dmesg | grep -ciE 'fw error|sysassert|recovery'" | sed "s/^/$n ошибок fw: /"; done
