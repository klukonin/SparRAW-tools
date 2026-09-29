#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# probe.sh HOST — снимок ключевых слов прямого линка (read-only)
H=$1
ssh -o ConnectTimeout=5 root@$(node $H) 'D=$(ls -d /sys/kernel/debug/ieee80211/phy*/wil6210|head -1)
r(){ echo "$1" > $D/mem_addr; cat $D/mem_val; }
for a in 0x941034 0x940ef4 0x940ef8 0x941b2c 0x886da4 0x9405d0 0x9405f0 0x9414d8 0x9410a4 0x91f848; do r $a; done
iw dev phy0-ap0 station dump | grep -E "packets|failed"'
