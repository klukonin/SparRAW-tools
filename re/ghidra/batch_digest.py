#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Сводка улик для списка адресов: вызывающие (с именами и файлами) и
вызываемые по именам. Вход: файл со списком адресов."""
import sys, collections, os
BASE=os.path.dirname(os.path.abspath(__file__))
syms={}
for line in open(BASE+'/SYMS-4100.txt'):
    if line.startswith('SYM'):
        p=line.split(); syms[int(p[1],16)]=(int(p[2]),p[-1])
fmap={}
for line in open(BASE+'/FN-FILEMAP-4100-EXT2.txt'):
    p=line.split()
    if len(p)>=2 and p[0].startswith('0x'): fmap[int(p[0],16)]=p[1]
rev=collections.defaultdict(set); fwd=collections.defaultdict(set)
for line in open(BASE+'/CALLGRAPH-4100.txt'):
    _,s,d=line.split(); s=int(s,16); d=int(d,16)
    if s!=d: rev[d].add(s); fwd[s].add(d)
SKIP=('__st_','__ld_','sub_','FUN_')
for l in open(sys.argv[1]):
    l=l.strip()
    if not l.startswith('0x'): continue
    a=int(l,16)
    cn=[]
    for c in sorted(rev[a]):
        n=syms.get(c,(0,'?'))[1]
        cn.append("%s%s"%(n,"["+fmap[c]+"]" if c in fmap else ""))
    dn=[syms.get(d,(0,'?'))[1] for d in sorted(fwd[a])]
    dn=[x for x in dn if not x.startswith(SKIP)]
    print("0x%06x %4dБ | зовут: %s"%(a,syms.get(a,(0,''))[0],", ".join(cn)[:96] if cn else "никто"))
    if dn: print("            зовёт: %s"%", ".join(dn[:5])[:96])
