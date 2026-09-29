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
FUN={0x8e5128:'mgmt_tx_submit', 0x8d5a40:'mgmt_build_frame', 0x8d5510:'mgmt_add_ie',
     0x8da130:'mgmt_tx_enqueue', 0x8da1f8:'mgmt_tx_enqueue_sta'}
for off,nm in FUN.items(): setfun(off,nm)
setPreComment(sp.getAddress(0x8e5128),'mgmt_tx_submit: WMI_SW_TX_REQ worker (module 0x27). '
  'find vif/STA, build frame desc (DA@-0x18 6B, subtype@-0x1c, mid@-0x12), enqueue TX.')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_','conn_','get_link','mgmt_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
