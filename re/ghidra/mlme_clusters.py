# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); mon=ConsoleTaskMonitor()
# IE constructors = callees of mgmt_add_ie in the 0x8d1e00-0x8d3000 cluster
f=fm.getFunctionAt(sp.getAddress(0x8d5510))
ie=sorted(set(c.getEntryPoint().getOffset() for c in f.getCalledFunctions(mon)
              if 0x8d1000<=c.getEntryPoint().getOffset()<0x8d3000))
print('IE constructors called by mgmt_add_ie: %d'%len(ie))
for a in ie: print('  0x%06x %s'%(a,fm.getFunctionAt(sp.getAddress(a)).getName()))
# frame builders = functions in 0x8d5000-0x8d6000 that call mgmt_add_ie or mgmt_tx path
print('\nRX dispatcher candidate 0x8d9f24 callees (frame parse?):')
g=fm.getFunctionAt(sp.getAddress(0x8d9f24))
if g:
    for c in sorted(set(c.getEntryPoint().getOffset() for c in g.getCalledFunctions(mon)))[:16]:
        print('  0x%06x %s'%(c,fm.getFunctionAt(sp.getAddress(c)).getName()))
# who calls mgmt_build_frame's neighbours -> senders
print('\ninternal mgmt senders FUN_008f3b84 / FUN_008f8ec0 - their names/size:')
for off in (0x8f3b84,0x8f8ec0,0x8fc3ec):
    fn=fm.getFunctionAt(sp.getAddress(off))
    if fn: print('  0x%06x %5dB %s'%(off,fn.getBody().getNumAddresses(),fn.getName()))
