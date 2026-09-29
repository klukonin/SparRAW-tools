# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
rm=currentProgram.getReferenceManager(); listing=currentProgram.getListing()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def fname(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    return f.getName() if f else 'FUN_%06x'%off
def callers(off):
    res=set()
    for r in rm.getReferencesTo(sp.getAddress(off)):
        f=fm.getFunctionContaining(r.getFromAddress())
        if f: res.add(f.getEntryPoint().getOffset())
    return sorted(res)
# is_pcp_ap predicate + trigger_bf + bcn_tx_init_ss + update_pcp_ap
DEC=[('is_pcp_ap?',0x8da488),('lmac_if_trigger_bf',0x8dc228),
     ('bcn_tx_init_ss_params',0x8c4664),('update_pcp_ap',0x8eac58),
     ('FUN_008c2778_bcn',0x8c2778),('FUN_008db04c',0x8db04c)]
for tag,off in DEC:
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('### %s @%06x NF'%(tag,off)); continue
    cl=sorted(set(fname(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    print('\n\n########## %s @0x%06x (%d B) calls: %s'%(tag,off,f.getBody().getNumAddresses(),', '.join(cl[:14])))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted(): print(r.getDecompiledFunction().getC())
print('\n\n===== callers of update_pcp_ap(0x8eac58) =====')
for c in callers(0x8eac58): print('  %s @0x%06x'%(fname(c),c))
print('===== callers of is_pcp_ap(0x8da488) =====')
for c in callers(0x8da488): print('  %s @0x%06x'%(fname(c),c))
