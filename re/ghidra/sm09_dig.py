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
# SM09 distinct actions in matrix order
acts=[('a0(S1.E7)',0x8c1fd0),('a1(S4.E7)',0x8c2004),('a2(S2/3.E7)',0x8c2078),
      ('a3(S0.E0 start)',0x8c2094),('a4(S4.E4)',0x8c2158),('a5(S1.E1/S5.E5)',0x8c2210),
      ('a6(S2.E2)',0x8c22f0),('a7(abort E6)',0x8c2310),('a8(S3.E3)',0x8c2358)]
for tag,off in acts:
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: continue
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    print('\n=== %s @0x%06x (%d B)  calls: %s'%(tag,off,f.getBody().getNumAddresses(),
          ', '.join(c for c in callees if not c.startswith('fw_log'))[:90]))
    r=dec.decompileFunction(f,25,mon)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n'):
            s=l.strip()
            if s and not s.startswith(('undefined','int ','uint ','void','{','}','/*','char','byte','func_0x008dc6c0','func_0x008dc6fc')):
                print('  '+s[:94])
