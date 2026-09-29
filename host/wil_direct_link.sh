#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
: "${NODE_AP:?задай NODE_AP — адрес узла AP (.11)}" "${NODE_STA:?задай NODE_STA — адрес узла STA (.12)}"; export NODE_AP NODE_STA
node() { case $1 in 11) echo "$NODE_AP";; 12) echo "$NODE_STA";; *) echo "$1";; esac; }
# direct_link.sh HOST [go]  -- on-node: find conn in READY_FOR_ASSOC and self-associate it
H=$1; GO=$2
ssh root@$(node $H) "D=\$(ls -d /sys/kernel/debug/ieee80211/phy*/wil6210|head -1); cat \$D/blob_fw_data" > /tmp/wil_dl_$H.bin
python3 - $H "$GO" <<'PY'
import struct,sys,subprocess
h,go=sys.argv[1],sys.argv[2]
d=open('/tmp/wil_dl_%s.bin'%h,'rb').read()
w=lambda a: struct.unpack_from('<I',d,a-0x800000)[0]
print('mode',w(0x805940))
writes=[]
for cid in range(8):
    c=w(0x8046a0+cid*8)
    if not c: continue
    st=w(c+0xfc)
    mac=struct.pack('<IH',w(c+0x10),w(c+0x14)&0xffff).hex(':')
    print('cid',cid,hex(c),mac,'connsm',st&0xff,'mlme',w(c+0xb0)&0xff,'+18',w(c+0x18),'+1c',w(c+0x1c))
    if (st&0xff)==3 and not writes:
        H=lambda a: '0x%x'%(a-0x800000+0x900000)
        writes=[(H(c+0xd8),'1'),('0x905940','1'),(H(c+0x18),'1'),(H(c+0x1c),'1'),(H(c+0xfc),'0x%08x'%((st&~0xff)|2))]
if go=='go' and writes:
    cmd='D=$(ls -d /sys/kernel/debug/ieee80211/phy*/wil6210|head -1); '+'; '.join('echo "%s %s" > $D/mem_write'%kv for kv in writes)
    print(cmd); subprocess.run(['ssh','root@192.168.1.'+h,cmd])
PY
