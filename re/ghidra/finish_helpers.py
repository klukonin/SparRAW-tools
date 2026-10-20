# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()

# 1) delete ALL stale wmi_helper_* labels (superseded by behaviour names)
deleted=0
for s in list(st.getAllSymbols(False)):
    if s.getName().startswith('wmi_helper_'):
        try: s.delete(); deleted+=1
        except: pass
print('deleted stale wmi_helper_* labels: %d' % deleted)

# 2) name the last helpers + the lookup they use
FUN={
 0x8ec380:'fw_delay',            # busy-wait loop, LP regs, 8e6 iters
 0x8cbe58:'fw_find_ctx_by_id',   # walk list, match id at entry+0x10
 0x8ebc20:'wmi_ctx_report',      # find ctx, read field @+0x48, send (tentative)
}
for off,nm in FUN.items():
    a=sp.getAddress(off); f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==off: f.setName(nm,SourceType.USER_DEFINED)
    else: createLabel(a,nm,True,SourceType.USER_DEFINED)
    print('0x%06x -> %s'%(off,nm))

import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','g_fw_log','g_tsf'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
# verify no dup addresses remain among our labels
from collections import Counter
dup=[a for a,c in Counter(a for a,_ in rows).items() if c>1]
print('map rows: %d ; addresses with >1 label: %d'%(len(rows),len(dup)))
for a in dup[:8]:
    print('   0x%06x: %s'%(a, ', '.join(n for x,n in rows if x==a)))
