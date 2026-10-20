# SPDX-License-Identifier: AGPL-3.0-or-later
# Decompile the WMI helpers and summarise each: size, callees (named if known),
# and pseudo-C head -- to infer their role (ack/reply, log, enqueue, alloc).
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
st = currentProgram.getSymbolTable()

def name_at(off):
    a = sp.getAddress(off)
    f = fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset() == off:
        return f.getName()
    ss = st.getSymbols(a)
    return ss[0].getName() if ss else 'FUN_%06x' % off

targets = [0x8c01d8, 0x8c93e8, 0x8d845c, 0x8dc6c0, 0x8e50d4, 0x8e90d0,
           0x8ebc20, 0x8ec380, 0x8e48ec]
dec = DecompInterface(); dec.openProgram(currentProgram)
mon = ConsoleTaskMonitor()
for off in targets:
    a = sp.getAddress(off)
    f = fm.getFunctionContaining(a)
    if f is None:
        print('\n=== 0x%06x : no function ===' % off); continue
    lbl = name_at(off)
    body = f.getBody()
    callees = sorted(set(name_at(c.getEntryPoint().getOffset())
                         for c in f.getCalledFunctions(mon)))
    print('\n=== 0x%06x %s  (%d bytes) ===' % (off, lbl, body.getNumAddresses()))
    print('calls: %s' % ', '.join(callees[:12]))
    res = dec.decompileFunction(f, 30, mon)
    if res and res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        # print first ~16 non-empty lines
        lines = [l for l in c.split('\n')]
        for l in lines[:20]:
            print('  ' + l[:100])
