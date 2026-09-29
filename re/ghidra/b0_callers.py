# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
rm=currentProgram.getReferenceManager()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: return f.getName()
    return 'FUN_%06x'%off
def callers(off):
    res=set()
    for r in rm.getReferencesTo(sp.getAddress(off)):
        f=fm.getFunctionContaining(r.getFromAddress())
        if f: res.add(f.getEntryPoint().getOffset())
    return sorted(res)
for tgt in (0x8f1e18,0x8e696c,0x8f706c,0x8f1f2c):
    print('\n=== callers of %s @0x%06x ==='%(nm(tgt),tgt))
    for c in callers(tgt): print('   %s @0x%06x'%(nm(c),c))
# decompile the connect WMI handler chain callers of 0x8f1e18
print('\n\n===== decompile callers of l2_mgr::connect (0x8f1e18) =====')
for c in callers(0x8f1e18):
    f=fm.getFunctionContaining(sp.getAddress(c))
    print('\n########## %s @0x%06x (%d B) ##########'%(nm(c),c,f.getBody().getNumAddresses()))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted(): print(r.getDecompiledFunction().getC())
