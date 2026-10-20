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
# 11 IE constructors (structural names; specific IE types = detail pass)
ies=[0x8d1ef0,0x8d1f24,0x8d20ec,0x8d2340,0x8d239c,0x8d289c,0x8d28b8,0x8d2c18,0x8d2d58,0x8d2e04,0x8d2f34]
for i,a in enumerate(ies): setfun(a,'mgmt_ie_%02d'%i)
# frame field builders + senders
setfun(0x8d545c,'mgmt_add_field'); setfun(0x8d54c4,'mgmt_add_field2'); setfun(0x8d5de8,'mgmt_build_body')
setfun(0x8fc3ec,'mgmt_send_frame')      # calls mgmt_build_frame
setfun(0x8f3b84,'mgmt_tx_internal'); setfun(0x8f8ec0,'mgmt_tx_internal2')
setPreComment(sp.getAddress(0x8d5510),'mgmt_add_ie: adds information elements to a mgmt frame; '
  'orchestrates 11 IE constructors mgmt_ie_00..10 (0x8d1ef0-0x8d2f34)')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_','conn_','get_link','mgmt_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
