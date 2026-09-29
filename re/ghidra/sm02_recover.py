# SPDX-License-Identifier: AGPL-3.0-or-later
# Reconstruct SM02 (link lifecycle) actions: decompile + name by matrix role.
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
# matrix roles (host addrs): SM02 3x4
ROLE={0x8c23b4:'link_start',      # S0.E0 -> CONNECTING
      0x8c2184:'link_advance',    # S1.E1 -> CONNECTED
      0x8c2128:'link_disconnect', # S2.E2 -> IDLE
      0x8c2038:'link_abort',      # S1.E3 -> IDLE
      0x8c2400:'link_retry',      # S2.E3 self
      0x8c9320:'sm_default_action'} # shared ignore/log
for off,role in ROLE.items():
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: continue
    r=dec.decompileFunction(f,20,mon)
    body=[]
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n'):
            s=l.strip()
            if s and not s.startswith(('undefined','int ','uint ','void','{','}','/*','char','byte')):
                body.append(s[:88])
    print('\n=== 0x%06x  role=%s (%d B) ==='%(off,role,f.getBody().getNumAddresses()))
    for b in body[:8]: print('  '+b)
    # name it
    nm='sm02_%s'%role if role!='sm_default_action' else 'sm_default_action'
    if f.getEntryPoint().getOffset()==off and (f.getName().startswith('FUN_') or f.getName().startswith('sm')):
        f.setName(nm,SourceType.USER_DEFINED)
print('\nnamed SM02 actions + default')
