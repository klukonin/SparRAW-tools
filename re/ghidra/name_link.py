# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
FUN={ 0x8cba98:'sta_lookup', 0x8d94b8:'sta_sm_post' }
DAT={ 0x8037b0:'g_dev_started',
      0x8012d9:'g_bf_cid', 0x8012da:'g_bf_sector',
      0x801254:'g_bf_sector_time', 0x801288:'g_bf_sector_cfg' }
for off,nm in FUN.items():
    a=sp.getAddress(off); f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==off: f.setName(nm,SourceType.USER_DEFINED)
    else: createLabel(a,nm,True,SourceType.USER_DEFINED)
    print('func 0x%06x -> %s'%(off,nm))
for off,nm in DAT.items():
    createLabel(sp.getAddress(off),nm,True,SourceType.USER_DEFINED); print('data 0x%06x -> %s'%(off,nm))
setPreComment(sp.getAddress(0x8eb830),
  'bf_control: programs 13-entry sector tables g_bf_sector_time(u32*1000)/g_bf_sector_cfg(u8)')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','g_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
