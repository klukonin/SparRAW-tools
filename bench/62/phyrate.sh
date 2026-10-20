# SPDX-License-Identifier: AGPL-3.0-or-later
# phyrate.sh N — N секунд, раз в секунду 14 счётчиков PHY; печатает сумму положительных приростов
D=/sys/kernel/debug/ieee80211/phy0/wil6210
N=${1:-20}
rd() { for a in 0x883964 0x883968 0x88396c 0x883970 0x883974 0x883978 0x88397c 0x8839a0 0x8839a4 0x8839a8 0x8839ac 0x8839b0 0x8839b4 0x8839b8; do echo $a > $D/mem_addr; v=$(cat $D/mem_val); echo -n "$((${v##*= })) "; done; }
prev=$(rd); set -- $prev; i=0; for k in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do eval s$k=0; done
while [ $i -lt $N ]; do sleep 1; cur=$(rd); k=1
  for v in $cur; do p=$(echo $prev | cut -d' ' -f$k); if [ $v -ge $p ]; then eval s$k=\$\(\(s$k+v-p\)\); else eval s$k=\$\(\(s$k+v\)\); fi; k=$((k+1)); done
  prev=$cur; i=$((i+1)); done
echo "SC: $s1 $s2 $s3 $s4 $s5 hdrerr=$s6 bernz=$s7 | CP: $s8 $s9 $s10 $s11 $s12 hdrerr=$s13 bernz=$s14  (за $N с)"
