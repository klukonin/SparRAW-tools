# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); rm=currentProgram.getReferenceManager()
listing=currentProgram.getListing()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def fname(off):
    f=fm.getFunctionContaining(sp.getAddress(off)); return f.getName() if f else 'FUN_%06x'%off
def callers(off):
    res=set()
    for r in rm.getReferencesTo(sp.getAddress(off)):
        f=fm.getFunctionContaining(r.getFromAddress())
        if f: res.add(f.getEntryPoint().getOffset())
    return sorted(res)
print('===== callers of lmac_if_trigger_bf(0x8dc228) =====')
for c in callers(0x8dc228): print('  %s @0x%06x'%(fname(c),c))
# decompile the BF trigger callers + config_txss + connect BF init candidates
CALL=callers(0x8dc228)
for off in CALL:
    f=fm.getFunctionContaining(sp.getAddress(off))
    print('\n\n########## caller %s @0x%06x (%d B) ##########'%(fname(off),off,f.getBody().getNumAddresses()))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted(): print(r.getDecompiledFunction().getC())
