# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); mon=ConsoleTaskMonitor()
dec=DecompInterface(); dec.openProgram(currentProgram)
for off in (0x8f3b84,0x8f8ec0):
    f=fm.getFunctionAt(sp.getAddress(off))
    r=dec.decompileFunction(f,45,mon)
    print('\n########## %s @0x%06x ##########'%(f.getName(),off))
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n'):
            s=l.strip()
            if s and not s.startswith(('undefined','int ','uint ','void','{','}','/*','char ','byte ','ushort','short','bool')):
                print('  '+s[:100])
