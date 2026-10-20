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
f=fm.getFunctionAt(sp.getAddress(0xa52d8))
callees=sorted(set(nm(c.getEntryPoint()) for c in f.getCalledFunctions(mon)))
print('FUN_0a52d8 (%dB) callees: %s'%(f.getBody().getNumAddresses(),', '.join(callees)))
r=dec.decompileFunction(f,90,mon)
if r and r.decompileCompleted():
    print(r.getDecompiledFunction().getC()[:2800])
