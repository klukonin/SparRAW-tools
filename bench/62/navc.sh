# SPDX-License-Identifier: AGPL-3.0-or-later
D=/sys/kernel/debug/ieee80211/phy0/wil6210
r() { echo $1 > $D/mem_addr; v=$(cat $D/mem_val); echo -n "$2=$((${v##*= })) "; }
r 0x941498 navtime_lo; r 0x94149c navtime_hi; r 0x941484 navmax; r 0x941486 clamps; r 0x941470 navend; r 0x94146c navflag; r 0x9422cc cts_fail; r 0x9422e4 tx_abort; r 0x9422e8 no_time; r 0x9410de txop_ok; r 0x9422f4 cts_sent; r 0x942304 rx_armed; r 0x9422d4 txvec; echo 0x941024 > $D/mem_addr; v=$(cat $D/mem_val); echo -n "rxcfg=${v##*= } "; echo 0x941110 > $D/mem_addr; v=$(cat $D/mem_val); echo -n "sta0_rxomni=${v##*= } "; echo
