# SPDX-License-Identifier: AGPL-3.0-or-later
# Name per-SM init functions and the SM registry; label state/event name tables.
# @category wil6210
# @runtime PyGhidra
import json, os
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing()
cat=json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json')))
smorder=sorted(cat,key=lambda x:(x['events'],x['states']))
want={sm['desc']-0x100000:i for i,sm in enumerate(smorder)}
def scalars(ins):
    out=[]
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try: out.append(o.getValue()&0xffffffff)
            except: pass
    return out
# find, per SM, the init function = the non-registry function referencing it
reg_lo,reg_hi=0x8c1700,0x8c1d00
inits={}
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next(); off=ins.getAddress().getOffset()
    for v in scalars(ins):
        if v in want:
            f=fm.getFunctionContaining(ins.getAddress())
            if f and not (reg_lo<=f.getEntryPoint().getOffset()<reg_hi):
                inits.setdefault(want[v],f.getEntryPoint().getOffset())
for i,sm in enumerate(smorder):
    # name name-tables
    createLabel(sp.getAddress(sm['state_names']+0x100000),'g_sm%02d_state_names'%i,True,SourceType.USER_DEFINED)
    createLabel(sp.getAddress(sm['event_names']+0x100000),'g_sm%02d_event_names'%i,True,SourceType.USER_DEFINED)
    if i in inits:
        f=fm.getFunctionContaining(sp.getAddress(inits[i]))
        if f and f.getName().startswith('FUN_'):
            f.setName('sm%02d_init'%i,SourceType.USER_DEFINED)
# name the registry function (contains the 0x8c1bxx refs)
rf=fm.getFunctionContaining(sp.getAddress(0x8c1bb2))
if rf and rf.getName().startswith('FUN_'): rf.setName('sm_registry_init',SourceType.USER_DEFINED)
# dump full map
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('inits named: %d ; total map rows: %d'%(len(inits),len(rows)))
