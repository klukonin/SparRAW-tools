#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# rxidx.sh IDX [СЕК] — на станции (.12) держать индекс RX-AWV в DTI = IDX:
# 0x941024 и поля станции 0 +0x08/+0x10 (host 0x941108/0x941110) = IDX<<8|0x20,
# перезапись каждые ~0.3 с; параллельно пинг и выборка 0x94212c (лучший сектор RSS).
IDX=$1; W=${2:-20}
V=$(printf '0x%08x' $(( (IDX<<8) | 0x20 )))
ssh root@$NODE_STA "D=/sys/kernel/debug/ieee80211/phy0/wil6210
  ( i=0; while [ \$i -lt $((W*3)) ]; do for a in 0x941024 0x941108 0x941110; do echo \"\$a $V\" > \$D/mem_write; done; i=\$((i+1)); done ) &
  ping -q -c $W -W 1 192.168.60.1 | grep loss &
  n=0; j=0; while [ \$j -lt 40 ]; do echo 0x94212c > \$D/mem_addr; v=\$(cat \$D/mem_val); [ \"\${v##*= }\" != 0x00000000 ] && n=\$((n+1)); j=\$((j+1)); done; echo \"ненулевой лучший сектор RSS: \$n/40\"
  wait"
