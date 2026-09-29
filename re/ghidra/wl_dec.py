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
for off in (0xa540c,):
    f=fm.getFunctionAt(sp.getAddress(off))
    callees=sorted(set(nm(c.getEntryPoint()) for c in f.getCalledFunctions(mon)))
    print('=== FUN_%06x callees: %s'%(off,', '.join(callees)))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted():
        c=r.getDecompiledFunction().getC()
        # print lines with calls, xor, key-ish, readFile, decrypt
        for l in c.split('\n'):
            s=l.strip()
            if any(k in s for k in ('readFile','FUN_','xor','XOR','^','decrypt','AES','key','memcpy','wil6210')) and '=' in s or 'FUN_' in s:
                print('  '+s[:110])
