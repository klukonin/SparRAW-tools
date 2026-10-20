# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
FUN={
 0x8dc6c0:'fw_log_trace0',   # rename from fw_log_trace: 0-arg variant
 0x8dc748:'fw_log_trace1',
 0x8dc7a0:'fw_log_trace2',
 0x8c93e8:'fw_assert',       # one-shot 0xdeaddead panic latch + TSF + log
 0x8d845c:'fw_assert_wrap',
}
for off,nm in FUN.items():
    a=sp.getAddress(off)
    for s in st.getSymbols(a):
        if s.getName().startswith(('wmi_helper_','fw_log_trace')) and s.getName()!=nm:
            try: s.delete()
            except: pass
    f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==off: f.setName(nm,SourceType.USER_DEFINED)
    else: createLabel(a,nm,True,SourceType.USER_DEFINED)
    print('0x%06x -> %s'%(off,nm))
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','g_fw_log','g_tsf'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
