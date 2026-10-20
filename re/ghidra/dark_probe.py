# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Скелет тёмного кластера: размеры, вызывающие, вызываемые, глобалы, соседи.
import sys
from collections import defaultdict
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
ref=currentProgram.getReferenceManager()
fmap={}
for l in open(getScriptArgs()[0]):
    p=l.split()
    if len(p)>=2 and p[0].startswith('0x'): fmap[int(p[0],16)]=p[1]
RANGES=[(int(a,16),int(b,16)) for a,b in (x.split('-') for x in getScriptArgs()[1].split(','))]

def nm(f):
    return f.getName() if f else '?'

for LO,HI in RANGES:
    print('\n########## кластер 0x%06x..0x%06x ##########'%(LO,HI))
    # соседи по файлам
    before=[a for a in sorted(fmap) if a<LO][-3:]
    after=[a for a in sorted(fmap) if a>HI][:3]
    print('соседи слева : %s'%', '.join('0x%06x=%s'%(a,fmap[a]) for a in before))
    print('соседи справа: %s'%', '.join('0x%06x=%s'%(a,fmap[a]) for a in after))
    for f in fm.getFunctions(True):
        off=f.getEntryPoint().getOffset()
        if not (LO<=off<HI): continue
        callers=set(); callees=set(); globs=set()
        for r in ref.getReferencesTo(f.getEntryPoint()):
            cf=fm.getFunctionContaining(r.getFromAddress())
            if cf and cf.getEntryPoint().getOffset()!=off: callers.add(cf)
        ins=listing.getInstructionAt(f.getEntryPoint())
        end=f.getBody().getMaxAddress().getOffset()
        while ins is not None and ins.getAddress().getOffset()<=end:
            for fl in (ins.getFlows() or []):
                t=fl.getOffset()
                if t<LO or t>=HI:
                    tf=fm.getFunctionContaining(fl)
                    if tf: callees.add(tf)
            for i in range(ins.getNumOperands()):
                for o in ins.getOpObjects(i):
                    try: v=o.getValue()
                    except Exception: continue
                    if isinstance(v,int) and 0x800000<=v<0x808000: globs.add(v)
                    elif isinstance(v,int) and 0x840000<=v<0x860000: globs.add(v)
            ins=ins.getNext()
        print('\n  0x%06x %-34s %5d Б'%(off,f.getName(),f.getBody().getNumAddresses()))
        print('    зовут  : %s'%(', '.join(sorted('%s@0x%06x'%(nm(c),c.getEntryPoint().getOffset()) for c in callers))[:150] or '(никто)'))
        print('    зовёт  : %s'%(', '.join(sorted('%s'%nm(c) for c in callees))[:150] or '-'))
        print('    глобалы: %s'%(', '.join('0x%06x'%g for g in sorted(globs))[:130] or '-'))
