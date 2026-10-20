# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import collections
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(off):
    a=sp.getAddress(off) if isinstance(off,(int,)) else off
    f=fm.getFunctionContaining(a); return f.getName() if f else '(top)'
# 1) decompile wmi_h_sw_tx_req (mgmt frame TX) and its worker
for lbl in ('wmi_h_sw_tx_req','wmi_h_set_appie'):
    s=st.getGlobalSymbols(lbl)
    if not s: continue
    f=fm.getFunctionAt(s[0].getAddress())
    callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    print('=== %s calls: %s'%(lbl,', '.join(c for c in callees if not c.startswith('fw_log'))[:100]))
# 2) find mgmt-subtype dispatchers: functions whose scalar operands include a
#    cluster of 802.11 mgmt subtypes {0,1,2,3,4,5,8,0xa,0xb,0xc,0xd}
MGMT={0,1,2,3,4,5,8,0xa,0xb,0xc,0xd}
perfunc=collections.defaultdict(set)
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next()
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try:
                v=o.getValue()&0xffffffff
                if v in MGMT:
                    f=fm.getFunctionContaining(ins.getAddress())
                    if f: perfunc[f.getEntryPoint().getOffset()].add(v)
            except: pass
cands=[(off,vs) for off,vs in perfunc.items() if len({x for x in vs if x in {0xa,0xb,0xc,0xd}})>=2 and len(vs)>=5]
cands.sort(key=lambda x:-len(x[1]))
print('\nmgmt-subtype dispatcher candidates (func, subtypes seen):')
for off,vs in cands[:10]:
    print('  0x%06x  %s  {%s}'%(off,nm(sp.getAddress(off)),','.join('0x%x'%v for v in sorted(vs))))
