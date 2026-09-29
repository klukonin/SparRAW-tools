# SPDX-License-Identifier: AGPL-3.0-or-later
D=/sys/kernel/debug/ieee80211/phy0/wil6210
for a in 0x883964 0x883968 0x88396c 0x883970 0x883974 0x883978 0x88397c 0x8839a0 0x8839a4 0x8839a8 0x8839ac 0x8839b0 0x8839b4 0x8839b8; do echo $a > $D/mem_addr; v=$(cat $D/mem_val); echo -n "${v##*= } "; done; echo
