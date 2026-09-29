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
# module init-callers per SM
targets={ 'SM00':0x8e6f80,'SM04':0x8f290c,'SM09':0x8f8f64,'SM10':0x8f4ecc,
          'SM14':0x8e5b88,'SM11':None }
# SM11 init<-sm14_init; find sm14_init's module caller
for tag,off in targets.items():
    if off is None: continue
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('%s: none'%tag); continue
    callers=set(nm(r.getFromAddress()) for r in ref.getReferencesTo(f.getEntryPoint()))
    # what WMI/named funcs are near / call this
    r=dec.decompileFunction(f,25,mon)
    print('\n=== %s init-caller %s @0x%06x  called-by: %s ==='%(tag,f.getName(),f.getEntryPoint().getOffset(),','.join(sorted(callers)[:4])))
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n')[:20]: print('  '+l[:100])
