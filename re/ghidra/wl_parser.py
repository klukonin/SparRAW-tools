# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
prog=currentProgram; fm=prog.getFunctionManager(); mon=ConsoleTaskMonitor()
sp=prog.getAddressFactory().getDefaultAddressSpace()
dec=DecompInterface(); dec.openProgram(prog)
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else 'sub_%x'%a.getOffset()
for off in (0x5aa64, 0xa52d8):
    f=fm.getFunctionAt(sp.getAddress(off))
    if not f: continue
    callees=sorted(set(nm(c.getEntryPoint()) for c in f.getCalledFunctions(mon)))
    print('\n===== FUN_%06x (%dB) callees: %s'%(off,f.getBody().getNumAddresses(),', '.join(callees)))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted():
        c=r.getDecompiledFunction().getC()
        print(c[:2600])
