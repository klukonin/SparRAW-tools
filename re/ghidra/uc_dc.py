# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); mon=ConsoleTaskMonitor()
dec=DecompInterface(); dec.openProgram(currentProgram)
for off in (0x925fdc, 0x930acc, 0x920260, 0x920264):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: continue
    r=dec.decompileFunction(f,20,mon)
    print('\n===== 0x%06x (%dB) ====='%(off,f.getBody().getNumAddresses()))
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n')[:18]:
            s=l.strip()
            if s and not s.startswith(('/*',)): print('  '+s[:96])
