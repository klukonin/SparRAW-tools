# SPDX-License-Identifier: AGPL-3.0-or-later
# MLME skeleton via call graph around anchors.
# @category wil6210
# @runtime PyGhidra
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); ref=currentProgram.getReferenceManager()
mon=ConsoleTaskMonitor()
def nm(a):
    f=fm.getFunctionContaining(a)
    return f.getName() if f else '(top)'
anchors={'mgmt_tx_submit':0x8e5128,'mgmt_build_frame':0x8d5a40,'mgmt_add_ie':0x8d5510}
for anm,off in anchors.items():
    f=fm.getFunctionAt(sp.getAddress(off))
    callers=set()
    for r in ref.getReferencesTo(f.getEntryPoint()):
        c=nm(r.getFromAddress())
        if c!=anm: callers.add(c)
    callees=sorted(set(nm(c.getEntryPoint()) for c in f.getCalledFunctions(mon)))
    callees=[c for c in callees if not c.startswith(('fw_log','fw_assert'))]
    print('\n### %s @0x%06x'%(anm,off))
    print('  callers (%d): %s'%(len(callers), ', '.join(sorted(callers)[:14])))
    print('  callees: %s'%', '.join(callees[:14]))
# also: what does mgmt_build_frame's cluster neighbours look like (0x8d5xxx)
print('\n### frame-builder cluster 0x8d5000-0x8d6000 (functions):')
fi=fm.getFunctions(sp.getAddress(0x8d5000),True)
cnt=0
for f in fi:
    if f.getEntryPoint().getOffset()>=0x8d6000: break
    print('  0x%06x %5dB %s'%(f.getEntryPoint().getOffset(),f.getBody().getNumAddresses(),f.getName()))
    cnt+=1
    if cnt>=20: break
