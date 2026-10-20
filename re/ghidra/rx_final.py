# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
import collections
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); ref=currentProgram.getReferenceManager()
def setfun(off,nm):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off and f.getName().startswith(('FUN_','mgmt_tx_internal')):
        f.setName(nm,SourceType.USER_DEFINED)
setfun(0x8f3b84,'mgmt_frame_respond')   # extract subtype, build+send response, post SM evt10
setfun(0x8f8ec0,'mgmt_frame_respond2')
setPreComment(sp.getAddress(0x8f3b84),
  'mgmt_frame_respond: RX mgmt handler. extract subtype (fc>>4&0xf); on assoc_resp(1) '
  'build+send response via mgmt_tx_submit; post event 10 to per-STA MLME SM at sta+0x104.')
# which SM sits at sta+0x104? find funcs referencing +0x104 near sm_post_event -> note in comment only
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_','conn_','get_link','mgmt_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
