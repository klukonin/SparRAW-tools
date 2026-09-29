# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
prog=currentProgram; fm=prog.getFunctionManager(); mon=ConsoleTaskMonitor()
sp=prog.getAddressFactory().getDefaultAddressSpace()
dec=DecompInterface(); dec.openProgram(prog)
f=fm.getFunctionAt(sp.getAddress(0xa540c))
r=dec.decompileFunction(f,120,mon)
if r and r.decompileCompleted():
    c=r.getDecompiledFunction().getC()
    lines=c.split('\n')
    # print the region around readFile and digest/update
    for i,l in enumerate(lines):
        if any(k in l for k in ('readFile','digest','update','xor','^ ',' ^','<< 0','>> ','& 0xff','SHA','md5','MD5','FUN_000a52d8','FUN_0004b1a4','FUN_00050170','memcpy','getBoardName')):
            print('%4d %s'%(i,l.strip()[:108]))
