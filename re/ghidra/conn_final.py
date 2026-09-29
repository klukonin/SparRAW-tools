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
FUN={0x8c02d4:'fw_get_time', 0x8e4e00:'wmi_emit_event', 0x8cc5b0:'get_link_status',
     0x8f9bc0:'conn_step_time_start', 0x8f9bfc:'conn_step_time_end',
     0x8f9d28:'conn_step_finalize', 0x8f9368:'conn_step_pop',
     0x8f9578:'conn_retry_or_fail', 0x8f93b0:'conn_reset', 0x8f9cc0:'conn_step_check'}
for off,nm in FUN.items(): setfun(off,nm)
DAT={0x842c74:'g_conn_sm_queue',0x857748:'g_conn_max_retries',
     0x84f114:'g_clock_src',0x8052d4:'g_conn_step_threshold'}
for off,nm in DAT.items(): createLabel(sp.getAddress(off+0x100000 if off<0x900000 else off),nm,True,SourceType.USER_DEFINED)
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_','conn_','get_link'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
