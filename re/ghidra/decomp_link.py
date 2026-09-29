# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: return f.getName()
    ss=st.getSymbols(sp.getAddress(off)); return ss[0].getName() if ss else 'FUN_%06x'%off
import sys
for off in [int(x,16) for x in sys.argv[1:]] if False else (0x8ccbd4,0x8ebb7c):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('== 0x%06x none'%off); continue
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    print('\n===== 0x%06x %s (%d B) ====='%(off,nm(off),f.getBody().getNumAddresses()))
    print('calls: %s'%', '.join(callees[:16]))
    r=dec.decompileFunction(f,45,mon)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n')[:40]:
            print(l[:108])
