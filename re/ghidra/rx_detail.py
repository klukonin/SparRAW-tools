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
setfun(0x8e976c,'mgmt_build_assoc_resp')   # builds assoc-response body
setfun(0x8c3564,'mgmt_alloc_frame')        # allocates a frame buffer
setPreComment(sp.getAddress(0x8f3b84),
  'mgmt_frame_respond RX dispatch: subtype=fc>>4&0xf. '
  'subtype 1(assoc_resp): mgmt_build_assoc_resp -> mgmt_tx_submit; sm_post_event(sta+0x104,code 10). '
  'subtype 10: mgmt_tx_submit; sm_post_event(sta+0x104,code 0xc). '
  'NOTE sm_post_event arg2 is a message CODE, not raw event index (mapped internally).')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_','conn_','get_link','mgmt_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
