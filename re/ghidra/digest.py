#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Сводка улик по тёмным функциям: кто зовёт, кого зовёт, какие строки рядом."""
import sys, struct, bisect, collections, os
BASE = os.path.dirname(os.path.abspath(__file__))
lo, hi, top = int(sys.argv[1],16), int(sys.argv[2],16), int(sys.argv[3])
syms=[]
for line in open(BASE+'/SYMS-4100.txt'):
    if line.startswith('SYM'):
        p=line.split(); syms.append((int(p[1],16),int(p[2]),p[-1]))
syms.sort(); starts=[s[0] for s in syms]
name={a:n for a,s,n in syms}
fmap={}
for line in open(BASE+'/FN-FILEMAP-4100-EXT2.txt'):
    p=line.split()
    if len(p)>=2 and p[0].startswith('0x'): fmap[int(p[0],16)]=p[1]
def own(a):
    i=bisect.bisect_right(starts,a)-1
    return syms[i] if i>=0 and a<syms[i][0]+syms[i][1] else None
rev=collections.defaultdict(set); fwd=collections.defaultdict(set)
for line in open(BASE+'/CALLGRAPH-4100.txt'):
    _,s,d=line.split(); s=int(s,16); d=int(d,16)
    if s!=d: rev[d].add(s); fwd[s].add(d)
fstr=collections.defaultdict(list)
for seg,b,tab in ((BASE+'/kit-4100/seg_008c0000.bin',0x8c0000,BASE+'/../../tools/fwlog-strings/fw-4.1.0.1000.bin'),
                  (BASE+'/kit-4100/seg_00920000.bin',0x920000,BASE+'/../../tools/fwlog-strings/ucode-4.1.0.1000.bin')):
    code=open(seg,'rb').read(); blob=open(tab,'rb').read()
    for i in range(0,len(code)-3,2):
        h,l=struct.unpack_from('<HH',code,i); v=(h<<16)|l
        if (v>>24)!=1: continue
        o=v&0xffffff
        if o>=len(blob) or (o and blob[o-1]!=0): continue
        e=blob.find(b'\0',o)
        try: s=blob[o:e].decode('ascii')
        except: continue
        f=own(b+i)
        if f and len(s)>=4: fstr[f[0]].append(s)
SKIP=('__st_','__ld_','softfloat','fwlog_emit','fwlog_nnl','memcpy_')
dark=[(sz,a) for a,sz,n in syms if lo<=a<hi and n.startswith('FUN_') and a not in fmap]
dark.sort(reverse=True)
print("тёмных в диапазоне: %d функций, %d Б\n"%(len(dark),sum(s for s,a in dark)))
for sz,a in dark[:top]:
    cn=["%s%s"%(name.get(c,'?'),"["+fmap[c]+"]" if c in fmap else "") for c in sorted(rev[a])]
    dn=[]
    for d in sorted(fwd[a]):
        t=name.get(d,'?')
        if t.startswith(SKIP): continue
        if t.startswith('FUN_') and fstr.get(d): t+='(«%s»)'%fstr[d][0][:24]
        dn.append(t)
    print("0x%06x %4dБ | зовут: %s"%(a,sz,", ".join(cn)[:104] if cn else "никто"))
    if dn: print("            зовёт: %s"%", ".join(dn[:5])[:150])
    if fstr.get(a): print("            строки: %s"%" | ".join(fstr[a][:2])[:110])
