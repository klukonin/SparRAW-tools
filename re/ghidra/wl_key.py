# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
prog=currentProgram; fm=prog.getFunctionManager(); ref=prog.getReferenceManager(); mon=ConsoleTaskMonitor()
sp=prog.getAddressFactory().getDefaultAddressSpace()
dec=DecompInterface(); dec.openProgram(prog)
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else 'sub_%x'%a.getOffset()
# who (transitively) calls the AES-CBC wrapper 0x127c0 and ECB 0x274d8 ? up to 2 hops
def callers_of(off):
    s=set()
    f=fm.getFunctionAt(sp.getAddress(off))
    for r in ref.getReferencesTo(f.getEntryPoint()):
        s.add(nm(r.getFromAddress()))
    return s
for off in (0x127c0,0x274d8):
    print('callers of FUN_%06x: %s'%(off,callers_of(off)))
# decompile the AES-CBC decrypt wrapper 0x127c0: find key & iv args
for off in (0x127c0,):
    f=fm.getFunctionAt(sp.getAddress(off))
    r=dec.decompileFunction(f,60,mon)
    print('\n===== FUN_%06x ====='%off)
    if r and r.decompileCompleted():
        print(r.getDecompiledFunction().getC()[:2000])
