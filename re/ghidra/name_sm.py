# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
# generic table-driven FSM engine (vendor basic_sm), used by the STA link SM
ren={0x8d94b8:'sm_post_event', 0x8c9bd4:'sm_step', 0x8dc8b4:'fw_log_trace3'}
for off,nm in ren.items():
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: f.setName(nm,SourceType.USER_DEFINED)
for off,c in {0x8d94b8:'generic FSM event post + queue drain (basic_sm); STA link SM lives at sta+0x104',
              0x8c9bd4:'generic FSM step: idx=state+event*nstates, 5B entry {next_state,action_ptr}, calls action'}.items():
    setPreComment(sp.getAddress(off),c)
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','g_','connect_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
