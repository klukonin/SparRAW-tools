# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
def setfun(off,nm):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off and f.getName().startswith('FUN_'):
        f.setName(nm,SourceType.USER_DEFINED); return True
    return False
setfun(0x8e0770,'fw_timer_arm')       # (callback, ctx, ?, ?, microseconds, ...)
# 0x26bb8 -> host 0x8e6bb8 connect-timeout callback
from ghidra.app.cmd.function import CreateFunctionCmd
a=sp.getAddress(0x8e6bb8)
if fm.getFunctionContaining(a) is None: CreateFunctionCmd(a).applyTo(currentProgram)
setfun(0x8e6bb8,'link_connect_timeout')
# comment on SM02 descriptor documenting the reconstructed lifecycle
setPreComment(sp.getAddress(0x902c9c),
  'SM02 vif link lifecycle: S0=IDLE S1=CONNECTING S2=CONNECTED. '
  'E0=start(arm 1s timer,->S1) E1=advance(post SM09 evt0,->S2) '
  'E2=disconnect(->S0) E3=abort/retry. Drives per-STA SM09 via sta+0x80.')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
