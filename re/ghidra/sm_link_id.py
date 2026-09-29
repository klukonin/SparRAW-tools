# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); ref=currentProgram.getReferenceManager()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else '(top)'
# the 3 link-SM (3x4) init functions
for lbl in ('sm00_init','sm01_init','sm02_init'):
    syms=st.getGlobalSymbols(lbl)
    if not syms: print('%s: not found'%lbl); continue
    ep=syms[0].getAddress()
    callers=set()
    for r in ref.getReferencesTo(ep):
        if r.getReferenceType().isCall() or True:
            callers.add(nm(r.getFromAddress()))
    print('\n=== %s @ %s  callers: %s'%(lbl, ep, ', '.join(sorted(callers)[:6]) or 'none'))
    f=fm.getFunctionAt(ep)
    if f:
        r=dec.decompileFunction(f,30,mon)
        if r and r.decompileCompleted():
            for l in r.getDecompiledFunction().getC().split('\n')[:16]: print('  '+l[:100])
