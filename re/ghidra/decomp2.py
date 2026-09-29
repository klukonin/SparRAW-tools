# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
dec = DecompInterface(); dec.openProgram(currentProgram); mon = ConsoleTaskMonitor()
for off in (0x8dc6c0, 0x8e90d0, 0x8c93e8, 0x8ec380, 0x8ebc20):
    f = fm.getFunctionContaining(sp.getAddress(off))
    if not f: 
        print('== 0x%06x none'%off); continue
    r = dec.decompileFunction(f, 30, mon)
    print('\n===== 0x%06x =====' % off)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n')[:26]:
            print(l[:104])
