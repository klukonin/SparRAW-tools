# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import re
from collections import Counter
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
fmap={}
for l in open(getScriptArgs()[0]):
    p=l.split()
    if len(p)>=2 and p[0].startswith('0x'): fmap[int(p[0],16)]=p[1]
want=set(getScriptArgs()[1].split(','))
regs=Counter()
seen=set()
for a,f in fmap.items():
    if f not in want: continue
    fn=fm.getFunctionContaining(sp.getAddress(a))
    if not fn: continue
    ep=fn.getEntryPoint().getOffset()
    if ep in seen: continue
    seen.add(ep)
    ins=listing.getInstructionAt(fn.getEntryPoint()); end=fn.getBody().getMaxAddress().getOffset()
    while ins is not None and ins.getAddress().getOffset()<=end:
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                try: v=o.getValue()
                except Exception: continue
                if isinstance(v,int) and 0x880000<=v<0x88d000: regs[v]+=1
        ins=ins.getNext()
print('РЕГИСТРЫ %s:'%'/'.join(want))
for a,c in sorted(regs.items()):
    print('  0x%06x ×%d'%(a,c))
