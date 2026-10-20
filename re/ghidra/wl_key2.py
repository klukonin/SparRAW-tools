# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
prog=currentProgram; fm=prog.getFunctionManager(); ref=prog.getReferenceManager(); mem=prog.getMemory(); mon=ConsoleTaskMonitor()
sp=prog.getAddressFactory().getDefaultAddressSpace()
dec=DecompInterface(); dec.openProgram(prog)
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else 'sub_%x'%a.getOffset()
# is the fw loader (a540c) transitively reaching 0x6add8/0xab658/0x127c0?
def reaches(src,dst,depth=3):
    seen=set(); frontier={src}
    for _ in range(depth):
        nxt=set()
        for off in frontier:
            f=fm.getFunctionAt(sp.getAddress(off))
            if not f: continue
            for c in f.getCalledFunctions(mon):
                o=c.getEntryPoint().getOffset()
                if o==dst: return True
                if o not in seen: seen.add(o); nxt.add(o)
        frontier=nxt
    return False
for dst in (0x127c0,0x6add8,0xab658):
    print('a540c reaches FUN_%06x: %s'%(dst,reaches(0xa540c,dst)))
# decompile callers of 127c0 to find param_1 (the key object) and the key bytes
for off in (0x6add8,0xab658):
    f=fm.getFunctionAt(sp.getAddress(off))
    r=dec.decompileFunction(f,50,mon)
    print('\n===== caller FUN_%06x (%dB) ====='%(off,f.getBody().getNumAddresses()))
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n'):
            s=l.strip()
            if 'FUN_000127c0' in s or '0x284' in s or 'DAT_' in s and '=' in s or 'wil' in s.lower():
                print('  '+s[:110])
