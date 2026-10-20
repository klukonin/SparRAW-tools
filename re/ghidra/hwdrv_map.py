# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Структурная карта драйверов железа: по функциям файлов hw_drivers_*.c/hw_flows_*
# собрать регистровые блоки (MMIO), которые они трогают, и точки входа.
import re,bisect
from collections import defaultdict
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
ref=currentProgram.getReferenceManager()
fmap={}
for l in open(getScriptArgs()[0]):
    p=l.split()
    if len(p)>=2 and p[0].startswith('0x'): fmap[int(p[0],16)]=p[1]
# регионы MMIO (CPU-пространство) — из sparrow_fw_mapping
def region(v):
    if 0x880000<=v<0x88a000: return 'rgf(MAC/PHY статус)'
    if 0x88a000<=v<0x88b000: return 'AGC_tbl'
    if 0x88b000<=v<0x88c000: return 'pcie_ext_rgf'
    if 0x88c000<=v<0x88d000: return 'mac_ext_rgf'
    if 0x840000<=v<0x860000: return 'fw_peri'
    return None
# сгруппировать функции по файлу
byfile=defaultdict(list)
for a,f in fmap.items():
    if f.startswith(('hw_drivers_','hw_flows_','marlon_r','brd_if')):
        byfile[f].append(a)
syms={}
for l in open(getScriptArgs()[1]):
    if l.startswith('SYM'):
        p=l.split(None,4); syms[int(p[1],16)]=int(p[2])
def scan(a):
    regs=defaultdict(int)
    f=fm.getFunctionContaining(sp.getAddress(a))
    if not f: return regs
    ins=listing.getInstructionAt(f.getEntryPoint()); end=f.getBody().getMaxAddress().getOffset()
    while ins is not None and ins.getAddress().getOffset()<=end:
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                try: v=o.getValue()
                except Exception: continue
                if isinstance(v,int):
                    r=region(v)
                    if r: regs[r]+=1
        ins=ins.getNext()
    return regs
print('%-34s %4s %6s  %s'%('файл','ф.','байт','регистровые блоки (обращений)'))
for f in sorted(byfile,key=lambda k:-sum(syms.get(a,0) for a in byfile[k])):
    fns=byfile[f]; tot=defaultdict(int)
    for a in fns:
        for r,c in scan(a).items(): tot[r]+=c
    b=sum(syms.get(a,0) for a in fns)
    rs=', '.join('%s×%d'%(r.split('(')[0],c) for r,c in sorted(tot.items(),key=lambda kv:-kv[1]))
    print('%-34s %4d %6d  %s'%(f,len(fns),b,rs or '—'))
