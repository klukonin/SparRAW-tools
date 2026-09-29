# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); ref=currentProgram.getReferenceManager()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(off):
    a=sp.getAddress(off) if isinstance(off,int) else off
    f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==(off if isinstance(off,int) else a.getOffset()): return f.getName()
    ss=st.getSymbols(a); return ss[0].getName() if ss else 'FUN_%06x'%(off if isinstance(off,int) else a.getOffset())
# 1) ucode subtype dispatcher candidate
for off in (0x92755c, 0x8f5610):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('0x%06x none'%off); continue
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    callers=sorted(set(nm(r.getFromAddress()) for r in ref.getReferencesTo(f.getEntryPoint())))
    print('\n===== 0x%06x %s (%d B)\n  callers: %s\n  callees: %s'%(off,nm(off),f.getBody().getNumAddresses(),
          ', '.join(callers[:6]), ', '.join(c for c in callees if not c.startswith('fw_log'))[:110]))
    r=dec.decompileFunction(f,35,mon)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n'):
            s=l.strip()
            if s and ('switch' in s or 'case' in s or '>> 4' in s or '& 0xf' in s or 'subtype' in s.lower() or '== ' in s):
                print('    '+s[:96])
