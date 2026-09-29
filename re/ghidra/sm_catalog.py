# SPDX-License-Identifier: AGPL-3.0-or-later
# Label the 15 SM descriptors + their action functions, and find who inits each
# (xref to the descriptor addr) -> identifies the STA/link SM.
# @category wil6210
# @runtime PyGhidra
import json, os
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
ref=currentProgram.getReferenceManager()
cat=json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json')))
def fnat(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else '(top)'
for i,sm in enumerate(sorted(cat,key=lambda x:(x['events'],x['states']))):
    da=sp.getAddress(sm['desc'])
    createLabel(da,'g_sm%02d_desc'%i,True,SourceType.USER_DEFINED)
    createLabel(sp.getAddress(sm['trans']),'g_sm%02d_trans'%i,True,SourceType.USER_DEFINED)
    for j,a in enumerate(sm['actions']):
        aa=sp.getAddress(a)
        if fm.getFunctionContaining(aa) is None: CreateFunctionCmd(aa).applyTo(currentProgram)
        f=fm.getFunctionContaining(aa)
        if f and f.getEntryPoint().getOffset()==a and f.getName().startswith('FUN_'):
            f.setName('sm%02d_act%d'%(i,j),SourceType.USER_DEFINED)
    # xref: who references the descriptor
    users=set()
    for r in ref.getReferencesTo(da):
        users.add(fnat(r.getFromAddress()))
    print('SM%02d %dx%d desc=0x%06x  users=%s'%(i,sm['states'],sm['events'],sm['desc'],
          ', '.join(sorted(users)[:4]) or 'none'))
