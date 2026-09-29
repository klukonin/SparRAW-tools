#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Запрет передачи по CID на время beamforming (прошивка 6.2 и 6.4): почему
# стоит юникаст к соседу.  Только чтение через debugfs mem_addr/mem_val.
# Раскладка — SparRAW-firmware/docs/DATAPATH.md §6, §8.
#
#   wil_tx_block.sh [CID]        # по умолчанию CID 0
#
# Юникаст запрещён, если у CID в маске запрета взведён бит 3 (BF) и очередь
# соседа (+0x18) вычтена из тени и регистра qset 6.  Пока байт причин BF не
# 0, запрет возвращается при каждом проходе передатчика.
CID=${1:-0}
D=$(find /sys/kernel/debug -maxdepth 4 -type d -name wil6210 2>/dev/null | head -1)
[ -f "$D/mem_addr" ] || { echo "нет debugfs wil6210"; exit 1; }

rd() { echo "$1" > "$D/mem_addr"; sed -n 's/.*= *\(0x[0-9a-fA-F]*\).*/\1/p' "$D/mem_val"; }
rd16() { # полуслово по произвольному адресу
	a=$(( $1 & ~3 )); s=$(( ($1 & 3) * 8 ))
	printf '0x%04x' $(( ($(rd $(printf '0x%x' $a)) >> s) & 0xffff ))
}
rd8() {
	a=$(( $1 & ~3 )); s=$(( ($1 & 3) * 8 ))
	printf '0x%02x' $(( ($(rd $(printf '0x%x' $a)) >> s) & 0xff ))
}

UC=0x940000                     # данные ucode для хоста
peer=$(( UC + 0x1104 + 0x50 * CID ))
echo "CID $CID ($(cat $D/fw_version))"
echo "  маска запрета TX 0x802a90[cid]:   $(rd16 $(( UC + 0x2a90 + 2 * CID )))   (бит 3 = BF)"
echo "  причины BF 0x857e49+0x14*cid:     $(rd8 $(( 0x857e49 + 0x14 * CID )))   (0 RS_MCS1_TH,1 NO_BACK,2 CTS_TXOP,3 BACK,4 FW,5 CTS_KA,6 ?)"
echo "  запись соседа +0x18 (qset 6):     $(rd $(printf '0x%x' $(( peer + 0x18 ))))"
echo "  запись соседа +0x1c (qset 5):     $(rd $(printf '0x%x' $(( peer + 0x1c ))))"
echo "  тень qset 5/6 0x801580/84:        $(rd $(( UC + 0x1580 )) ) $(rd $(( UC + 0x1584 )))"
echo "  регистры qset 3..7 0x886d98..a8:  $(for a in 0x886d98 0x886d9c 0x886da0 0x886da4 0x886da8; do printf '%s ' $(rd $a); done)"
echo "  включённые qset [gp-0x7c]:        $(rd $(( UC + 0x4ac )))"
echo "  LMAC_PASSIVE [gp+0xb4]:           $(rd $(( UC + 0x5dc )))"
echo "  data-qid соседа 0x801be8+5*cid:   $(rd8 $(( UC + 0x1be8 + 5 * CID )))"
