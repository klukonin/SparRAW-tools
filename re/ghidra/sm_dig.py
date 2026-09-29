# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
# create connect_work function if missing
for off in (0x8df218,):
    if fm.getFunctionContaining(sp.getAddress(off)) is None:
        CreateFunctionCmd(sp.getAddress(off)).applyTo(currentProgram)
# name the SM engine bits
for off,nm in {0x8c9bd4:'sta_sm_run',0x8ca874:'sm_queue_pop'}.items():
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: f.setName(nm,SourceType.USER_DEFINED)
for off,nm in {0x803868:'g_sta_sm_transitions',0x803854:'g_sta_sm_queue'}.items():
    createLabel(sp.getAddress(off),nm,True,SourceType.USER_DEFINED)
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: return f.getName()
    ss=st.getSymbols(sp.getAddress(off)); return ss[0].getName() if ss else 'FUN_%06x'%off
for off in (0x8c9bd4,0x8df218):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('== 0x%06x none'%off); continue
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    print('\n===== 0x%06x %s (%d B) ====='%(off,nm(off),f.getBody().getNumAddresses()))
    print('calls: %s'%', '.join(callees[:16]))
    r=dec.decompileFunction(f,50,mon)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n')[:40]:
            print(l[:110])
