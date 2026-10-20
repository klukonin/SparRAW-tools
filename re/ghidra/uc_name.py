# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
def setfun(off,nm):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off and f.getName().startswith('FUN_'):
        f.setName(nm,SourceType.USER_DEFINED)
setfun(0x925fdc,'uc_assert')
setfun(0x920260,'uc_ret_stub'); setfun(0x920264,'uc_ret_stub2')
# name the biggest handlers structurally (roles = detail later)
for i,off in enumerate((0x930acc,0x932488,0x92f884,0x926620,0x924a94)):
    setfun(off,'uc_handler_%d'%i)
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_','conn_','get_link','mgmt_','uc_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
