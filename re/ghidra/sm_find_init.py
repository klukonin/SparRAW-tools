# SPDX-License-Identifier: AGPL-3.0-or-later
# Find who initialises each SM: scan code for a scalar operand equal to the
# descriptor's LINKER address (desc_host - 0x100000). The containing function
# names the SM (the STA link SM among the 3x4 candidates).
# @category wil6210
# @runtime PyGhidra
import json, os
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager()
listing=currentProgram.getListing()
cat=json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json')))
# map linker-desc-addr -> sm index (sorted same as catalog labeling)
smorder=sorted(cat,key=lambda x:(x['events'],x['states']))
want={}
for i,sm in enumerate(smorder):
    want[sm['desc']-0x100000]=i   # linker addr
    want[sm['desc']]=i            # host addr too, just in case
def scalars(ins):
    out=[]
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try: out.append(o.getValue()&0xffffffff)
            except: pass
    return out
hits={}
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next()
    for v in scalars(ins):
        if v in want:
            f=fm.getFunctionContaining(ins.getAddress())
            hits.setdefault(want[v],[]).append((ins.getAddress().getOffset(), f.getName() if f else '(top)'))
for i in sorted(hits):
    sm=smorder[i]
    print('SM%02d %dx%d (desc lnk 0x%06x): referenced by'%(i,sm['states'],sm['events'],sm['desc']-0x100000))
    for a,fn in hits[i][:4]: print('    0x%06x %s'%(a,fn))
print('SMs with an init reference: %d/15'%len(hits))
