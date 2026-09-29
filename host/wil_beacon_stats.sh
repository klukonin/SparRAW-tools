#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Читает телеметрию распределённого биконинга wil6210 через debugfs mem_addr/memread.
# Адреса соответствуют FW 4.1.0.1000 (блок публикуемых счётчиков @0x854de0,
# регион fw_peri 0x840000..0x860000 — доступен хосту через wmi_addr_remap).
# На других версиях прошивки раскладка ДРУГАЯ.
#
# Использование:  ./wil_beacon_stats.sh [путь_к_debugfs_каталогу_wil6210]
#                 ./wil_beacon_stats.sh          # автопоиск
#                 watch -n1 ./wil_beacon_stats.sh

D="$1"
[ -z "$D" ] && D=$(find /sys/kernel/debug -maxdepth 4 -type d -name wil6210 2>/dev/null | head -1)
if [ -z "$D" ] || [ ! -f "$D/mem_addr" ]; then
    echo "не найден debugfs wil6210 (обычно /sys/kernel/debug/ieee80211/phyN/wil6210)"; exit 1
fi

rd() {   # rd <addr> -> печатает 32-битное слово в hex без 0x
    echo "$1" > "$D/mem_addr" 2>/dev/null || return 1
    v=$(cat "$D/memread" 2>/dev/null | sed -n 's/.*= 0x\([0-9a-fA-F]*\).*/\1/p')
    [ -z "$v" ] && v="INVALID"
    echo "$v"
}
h2d() { [ "$1" = "INVALID" ] && echo 0 || printf '%d' "0x$1"; }
byte() { # byte <word_hex> <index0..3>  (little-endian)
    w=$1; i=$2
    [ "$w" = "INVALID" ] && { echo 0; return; }
    printf '%d' "0x$(echo "$w" | sed "s/^\(.\{$((6-2*i))\}\)\(..\).*/\2/")" 2>/dev/null || echo 0
}

BM_LO=$(rd 0x854de4); BM_HI=$(rd 0x854de8)
BTI_LO=$(rd 0x854dec); BTI_HI=$(rd 0x854df0); BTI_DUR=$(rd 0x854df4)
W_BCON=$(rd 0x854e08)          # [0]=tx bcon [1]=rx bcon [2]=detected
AW_LO=$(rd 0x854e0c); AW_HI=$(rd 0x854e10); AW_DUR=$(rd 0x854e14)
W_ATIM1=$(rd 0x854e18)         # [0]=backoff [1]=atim pass [2]=atim fail [3]=atim cnt
W_ATIM2=$(rd 0x854e1c)         # [0]=rx atim [1]=bcons_atim_fail_vec

echo "=== wil6210 distributed-beacon telemetry (FW 4.1.0.1000) ==="
echo "debugfs: $D"
printf 'bcon bitmap   : 0x%s %s        <- битмап услышанных соседей (64 бита)\n' "$BM_HI" "$BM_LO"
printf 'tx bcon       : %s\n' "$(byte "$W_BCON" 0)"
printf 'rx bcon       : %s            <- принято чужих маяков\n' "$(byte "$W_BCON" 1)"
printf 'detected      : %s            <- обнаружено соседей\n' "$(byte "$W_BCON" 2)"
printf 'BTI start/dur : 0x%s%s / %s\n' "$BTI_HI" "$BTI_LO" "$(h2d "$BTI_DUR")"
printf 'AW  start/dur : 0x%s%s / %s\n' "$AW_HI" "$AW_LO" "$(h2d "$AW_DUR")"
printf 'backoff       : %s\n' "$(byte "$W_ATIM1" 0)"
printf 'tx atim p/f/c : %s / %s / %s\n' "$(byte "$W_ATIM1" 1)" "$(byte "$W_ATIM1" 2)" "$(byte "$W_ATIM1" 3)"
printf 'rx atim       : %s\n' "$(byte "$W_ATIM2" 0)"
printf 'atim fail vec : 0x%x          <- битовая маска проблемных соседей\n' "$(byte "$W_ATIM2" 1)"
echo
echo "КРИТЕРИЙ: распределённый биконинг жив, если на ОБОИХ узлах растут"
echo "          rx bcon / detected и заполняется bcon bitmap."
