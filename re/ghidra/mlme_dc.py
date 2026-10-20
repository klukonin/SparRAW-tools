# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(off):
    a=sp.getAddress(off) if isinstance(off,int) else off
    f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==(off if isinstance(off,int) else a.getOffset()): return f.getName()
    ss=st.getSymbols(a); return ss[0].getName() if ss else 'FUN_%06x'%(off if isinstance(off,int) else a.getOffset())
for off in (0x8d5a40, 0x8e5128, 0x8d9f24):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('0x%06x none'%off); continue
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    print('\n===== 0x%06x %s (%d B) calls: %s'%(off,nm(off),f.getBody().getNumAddresses(),
          ', '.join(c for c in callees if not c.startswith('fw_log'))[:100]))
    r=dec.decompileFunction(f,40,mon)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n'):
            s=l.strip()
            if s and not s.startswith(('undefined','int ','uint ','void','{','}','/*','char','byte','func_0x008dc6')):
                print('  '+s[:98])
