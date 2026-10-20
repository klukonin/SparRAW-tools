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
tgts=[('connect_work',0x8e551c),('step_9cc0',0x8f9cc0),('step_9bc0',0x8f9bc0),
      ('step_9bfc',0x8f9bfc),('step_9d28',0x8f9d28),('finish_9368',0x8f9368),('cleanup_9578',0x8f9578)]
for tag,off in tgts:
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('%s none'%tag); continue
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    callees=[c for c in callees if not c.startswith('fw_log')]
    print('\n=== %s @0x%06x (%d B)  calls: %s'%(tag,off,f.getBody().getNumAddresses(),', '.join(callees[:12])))
    r=dec.decompileFunction(f,30,mon)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n'):
            s=l.strip()
            if s and not s.startswith(('undefined','int ','uint ','void','{','}','/*','char','byte','func_0x008dc6','fw_log')):
                print('  '+s[:96])
