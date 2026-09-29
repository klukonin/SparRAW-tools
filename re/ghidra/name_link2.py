# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
def setfun(off,nm):
    a=sp.getAddress(off); f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==off: f.setName(nm,SourceType.USER_DEFINED)
    else: createLabel(a,nm,True,SourceType.USER_DEFINED)
    print('0x%06x -> %s'%(off,nm))
setfun(0x8dc5b4,'fw_post_work')          # schedules a callback work item
setfun(0x8df218,'connect_work')          # deferred connect handler (0x1f218)
setPreComment(sp.getAddress(0x8ccbd4),
  'connect: defers to connect_work via fw_post_work; fw_assert if already connecting')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','g_','connect_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
