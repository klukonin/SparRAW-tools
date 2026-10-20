# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
f=fm.getFunctionContaining(sp.getAddress(0x8d8e10))
if f and f.getName().startswith('FUN_'): f.setName('sm_init',SourceType.USER_DEFINED)
# tag SM02 as the leading link-SM candidate
setPreComment(sp.getAddress(0x902c9c),'SM02 (3 states x 4 events): leading STA link-SM candidate '
  '(SM00=boot/calib per RGF reads, SM01=sub-SM of SM12). Events 0..3 match sm_post_event assert.')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
