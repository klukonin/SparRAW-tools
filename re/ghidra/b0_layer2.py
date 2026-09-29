# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: return f.getName()
    ss=st.getSymbols(sp.getAddress(off)); return ss[0].getName() if ss else 'FUN_%06x'%off
TG=[('bss_mode_cfg_008e73a0',0x8e73a0),('pcp_start_inner_008e0778',0x8e0778),
    ('nettype_ie_008cccbc',0x8cccbc),('state_set_008e6358',0x8e6358),
    ('conn_cfg_008e6368',0x8e6368),('conn_cfg2_008e70a8',0x8e70a8),
    ('conn_finalize_008e6cec',0x8e6cec)]
for tag,off in TG:
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('### %s @0x%06x NOT FOUND'%(tag,off)); continue
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    print('\n\n########## %s @0x%06x (%d B) calls: %s'%(tag,off,f.getBody().getNumAddresses(),', '.join(callees[:14])))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted(): print(r.getDecompiledFunction().getC())
    else: print('  <decompile failed>')
